#include "plugin.h"

#include <Psapi.h>
#include <Shlwapi.h>
#include <string>
#include <vector>

////////////////////////////////////////////////////////////////////////////////
//
// global vars
//

/* currently not used */
// set in CBCREATEPROCESS.
static HANDLE hProcess = nullptr;

/* currently not used */
// if we're attaching to this name, attempt to auto deobfuscate & label imports.
// see CBATTACH and CBCREATEPROCESS.
static const char* overwatchModuleName = "Overwatch.exe";

/* currently not used */
// idk how to get the debuggee's name in CBATTACH, so set this if we're attaching.
// CBCREATEPROCESS will check this var, if true it will attempt to auto deobfuscate
// and label overwatch's imports.
static bool isAttaching = false;

// generated label addresses.  used to remove added labels when user stops debugging.
static std::vector<duint> importLabelAddresses;

// exported plugin command
static const char* cmdUnpackOverwatchImports = "oiu";

////////////////////////////////////////////////////////////////////////////////
//
// types
//

enum {
    PLUGIN_MENU_ABOUT,
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

// required x64dbg plugin funcs
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

// plugin exports
PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info);
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info);

// added commands
static bool cbUnpackOverwatchImports(int argc, char* argv[]);

// deobfuscation
duint FindIATBaseAddress();
bool MemRegionIsOverwatchIAT(const MEMORY_BASIC_INFORMATION& mbi);
duint DeobfuscateImportAddress(duint obfuscatedAddress, duint key, std::string op);
bool DeobfuscateImportBlock(duint blockBase, duint& importAddress, duint& nextImportBlockAddress);
void UnpackOverwatchImports(duint regionBase);

// misc utils
void RemoveLabels();
bool LabelImport(duint thunkAddress, duint actualImportAddress);
std::string GetMnemonic(const DISASM_INSTR& disasm);
std::string GetModuleNameFromAddress(duint address);
std::string GetLabelFromAddress(duint address);
std::string GenerateMysteryLabelName(duint address);

// unimplemented or not currently used stuff for automatically unpacking during attach
PLUG_EXPORT void _CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH* dwProcessId);
PLUG_EXPORT void _CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info);
std::string GetSymbolNameFromAddressDuringAttach(duint address);
std::string GetModuleNameFromAddressDuringAttach(duint address);

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

////////////////////////////////////////////////////////////////////////////////
//
// required x64dbg plugin funcs
//

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if (!_plugin_registercommand(pluginHandle, cmdUnpackOverwatchImports, cbUnpackOverwatchImports, true))
    {
        plog("[" PLUGIN_NAME "]:  failed to register command %s.\n", cmdUnpackOverwatchImports);
        return false;
    }
    return true;
}

bool pluginStop()
{
    _plugin_menuclear(hMenu);
    _plugin_unregistercommand(pluginHandle, cmdUnpackOverwatchImports);
    return true;
}

void pluginSetup()
{
    _plugin_menuaddentry(hMenu, PLUGIN_MENU_ABOUT, "&About");
}

////////////////////////////////////////////////////////////////////////////////
//
// plugin exports
//

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    hProcess = nullptr;
    RemoveLabels();
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case PLUGIN_MENU_ABOUT:
        MessageBoxA(hwndDlg,
                    "author:  qwerty9384.\n\npm me @ unknowncheats.me if you have questions.\n\nsource code:  https://github.com/qwerty9384/Overwatch-IAT-Deobfuscation.",
                    "About",
                    0);
        break;
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// added commands
//

// 'oiu' cmd
static bool cbUnpackOverwatchImports(int argc, char* argv[])
{
    duint iat = FindIATBaseAddress();
    if (!iat)
    {
        plog("[" PLUGIN_NAME "]:  failed to find mem region containing IAT.\n");
        return false;
    }
    //plog("[" PLUGIN_NAME "]:  found overwatch IAT at %p.\n", iat);
    RemoveLabels();
    UnpackOverwatchImports(iat);
    GuiUpdateDisassemblyView();
    plog("[" PLUGIN_NAME "]:  added %i labels.\n", importLabelAddresses.size());
    return true;
}

////////////////////////////////////////////////////////////////////////////////
//
// deobfuscation
//

duint FindIATBaseAddress()
{
    duint iat = 0;
    MEMMAP memmap;
    if (DbgMemMap(&memmap))
    {
        // iterate mapped memory regions
        for (int i = 0; i < memmap.count; i++)
        {
            MEMPAGE* p = &memmap.page[i];
            if (MemRegionIsOverwatchIAT(p->mbi))
            {
                iat = (duint)p->mbi.BaseAddress;
                break;
            }
        }
    }
    return iat;
}

/*
    11.30.2016

    memmap dump of the IAT region
    Address = 00000000001B0000
    Size = 0000000000003000
    Allocation Type = PRV
    Current Protection = ERW--      (PAGE_EXECUTE_READWRITE  0x40)
    Allocation Protection = ERW--   (PAGE_EXECUTE_READWRITE  0x40)

    first two imports
    00000000001B0000 | 48 B8 E2 2C E5 FA FE 07 00 00       | movabs  rax, iphlpapi.7FEFAE52CE2 |
    00000000001B000A | 48 35 CE 55 00 00                   | xor     rax, 55CE                 |
    00000000001B0010 | 73 02                               | jae     1B0014                    |
    00000000001B0012 | 48 B8 FF E0 48 B8 F0 80 52 FA       | movabs  rax, FA5280F0B848E0FF     |
    00000000001B001C | FE 07                               | inc     byte ptr ds:[rdi]         |
    00000000001B001E | 00 00                               | add     byte ptr ds:[rax], al     |
    00000000001B0020 | 48 05 78 26 00 00                   | add     rax, 2678                 |
    00000000001B0026 | 73 02                               | jae     1B002A                    |
*/
bool MemRegionIsOverwatchIAT(const MEMORY_BASIC_INFORMATION& mbi)
{
    // hardcoded values used to find IAT.  if the plugin breaks after an update then fix this.
    static const SIZE_T iatRegionSize = 0x3000;
    static const int iatProtectFlags = PAGE_EXECUTE_READWRITE;

    if (mbi.RegionSize != iatRegionSize)
        return false;

    if ((mbi.Protect & iatProtectFlags) == 0)
        return false;
    
    //plog("[" PLUGIN_NAME "]:  found potential IAT location at %p.\n", mbi.BaseAddress);

    // 11.30.2016: I've started seeing empty regions of size 0x3000 which appear before the IAT.
    const int nbytes = 20;
    BYTE bytes[nbytes] = {0};
    if (DbgMemRead((duint)mbi.BaseAddress, bytes, nbytes))
    {
        BYTE zeroes[nbytes] = {0};
        if (!memcmp(bytes, zeroes, nbytes))
            return false;
    }
    else
    {
        plog("[" PLUGIN_NAME "]:  failed reading memory at %p while validating IAT region.\n", mbi.BaseAddress);
        return false;
    }

    return true;
}

duint DeobfuscateImportAddress(duint obfuscatedAddress, duint key, std::string op)
{
    duint import = 0;
    if (op == "xor")
        import = obfuscatedAddress ^ key;
    else if (op == "add")
        import = obfuscatedAddress + key;
    else if (op == "sub")
        import = obfuscatedAddress - key;

    return import;
}

// sets importAddress and nextImportBlockAddress if block was successfully deobfuscated
bool DeobfuscateImportBlock(duint blockBase, duint& importAddress, duint& nextImportBlockAddress)
{
    duint ea = blockBase;
    DISASM_INSTR disasm;
    DbgDisasmAt(ea, &disasm);
    const duint obfuscated = disasm.arg[1].value;
    //plog("part 1:  %p\n", ea);

    ea += disasm.instr_size;
    DbgDisasmAt(ea, &disasm);
    const std::string op = GetMnemonic(disasm);
    const duint key = disasm.arg[1].value;
    //plog("part 2:  %p\n", ea);

    ea += disasm.instr_size;
    DbgDisasmAt(ea, &disasm);
    const duint jaedst = disasm.arg[0].value;
    //plog("part 3:  %p\n", ea);

    importAddress = DeobfuscateImportAddress(obfuscated, key, op);
    if (!importAddress)
        return false;

    nextImportBlockAddress = jaedst + 0x2;
    //plog("part 4:  %p\n", ea);

    return true;
}

void UnpackOverwatchImports(duint regionBase)
{
    const HANDLE hProcess = (HANDLE)DbgValFromString("$hProcess");
    if (!hProcess)
    {
        plog("[" PLUGIN_NAME "]:  $hProcess returned 0, exiting.\n", hProcess);
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProcess, (void*)regionBase, &mbi, sizeof(mbi)))
    {
        plog("[" PLUGIN_NAME "]:  VirtualQueryEx failed while unpacking imports, exiting.\n");
        return;
    }

    duint ea = regionBase;
    const duint regionEnd = (duint)mbi.BaseAddress + mbi.RegionSize;

    while (ea < regionEnd)
    {
        // stop when effective address contains null bytes.
        char nullcheck[MAX_COMMAND_LINE_SIZE] = {0};
        _snprintf(nullcheck, MAX_COMMAND_LINE_SIZE, "[%llx]", ea);
        if (DbgValFromString(nullcheck) == 0)
            break;

        duint importAddress = 0;
        duint nextBlockAddress = 0;
        if (!DeobfuscateImportBlock(ea, importAddress, nextBlockAddress))
        {
            plog("[" PLUGIN_NAME "]:  couldn't deobfuscate import block at %p, exiting.\n", ea);
            break;
        }

        if (!LabelImport(ea, importAddress))
            plog("[" PLUGIN_NAME "]:  failed to label import %p at %p.\n", importAddress, ea);

        ea = nextBlockAddress;
    }

    if (ea >= regionEnd)
    {
        plog("[" PLUGIN_NAME "]:  abnormal result, iterated over entire memory region while unpacking.\n");
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// misc utils
//

void RemoveLabels()
{
    if (importLabelAddresses.size() == 0)
        return;

    int i = 0;
    for (auto address : importLabelAddresses)
    {
        if (!DbgSetLabelAt(address, ""))
            plog("[" PLUGIN_NAME "]:  failed to remove import label at %p.\n", address);
        else
            i++;
    }

    importLabelAddresses.clear();
    plog("[" PLUGIN_NAME "]:  removed %i labels.\n", i);
}

// labels format:  module_name.function_name
bool LabelImport(duint thunkAddress, duint actualImportAddress)
{
    std::string importModuleName = GetModuleNameFromAddress(actualImportAddress);
    if (importModuleName.empty())
        importModuleName = "unkmod";

    // as of 12.1.2016 overwatch has 1 import from itself (overwatch.exe).
    std::string importFunctionName = GetLabelFromAddress(actualImportAddress);
    if (importFunctionName.empty())
        importFunctionName = GenerateMysteryLabelName(actualImportAddress);

    const std::string label = importModuleName + "." + importFunctionName;

    plog("[" PLUGIN_NAME "]:  %p  actual = %p  %s\n", thunkAddress, actualImportAddress, label.c_str());

    if (!DbgSetLabelAt(thunkAddress, label.c_str()))
        return false;

    importLabelAddresses.push_back(thunkAddress);
    return true;
}

std::string GetMnemonic(const DISASM_INSTR& disasm)
{
    int i = 0;
    while (disasm.instruction[i] != ' ') i++;
    return std::string(disasm.instruction, disasm.instruction + i);
}

std::string GetModuleNameFromAddress(duint address)
{
    char module[MAX_MODULE_SIZE] = {0};
    if (DbgGetModuleAt(address, module))
        return std::string(module);
    return std::string();
}

std::string GetLabelFromAddress(duint address)
{
    char label[MAX_LABEL_SIZE] = {0};
    if (DbgGetLabelAt(address, SEG_DEFAULT, label))
        return std::string(label);
    return std::string();
}

// generate name for addresses without symbol names
std::string GenerateMysteryLabelName(duint address)
{
    static duint mysteryCount = 0;
    mysteryCount++;
    return std::string("mystery_fn_") + std::to_string(mysteryCount);
}

////////////////////////////////////////////////////////////////////////////////
//
// unimplemented or not currently used stuff for automatically unpacking during attach
//

PLUG_EXPORT void _CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH* dwProcessId)
{
    return;

    isAttaching = true;
}

PLUG_EXPORT void _CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
{
    return;

    if (!isAttaching)
        return;

    hProcess = info->fdProcessInfo->hProcess;
    plog("[" PLUGIN_NAME "]:  hProcess = %x.\n", hProcess);

    // extra effort to get loaded image name with extension
    char loadedImageNameNoPath[MAX_PATH] = {0};
    memcpy(loadedImageNameNoPath, info->modInfo->LoadedImageName, MAX_PATH);
    PathStripPath(loadedImageNameNoPath);

    // attempt to deobfuscate and label the IAT
    if (!strncmp(overwatchModuleName, loadedImageNameNoPath, sizeof(overwatchModuleName)))
    {
        plog("[" PLUGIN_NAME "]:  attempting to deobfuscate and label overwatch imports.\n");

        MEMMAP memmap;
        if (DbgMemMap(&memmap))
        {
            // iterate mapped memory regions
            for (int i = 0; i < memmap.count; i++)
            {
                MEMPAGE* p = &memmap.page[i];
                if (MemRegionIsOverwatchIAT(p->mbi))
                {
                    plog("[" PLUGIN_NAME "]:  found overwatch IAT at %p.\n", p->mbi.BaseAddress);
                    UnpackOverwatchImports((duint)p->mbi.BaseAddress);
                    plog("[" PLUGIN_NAME "]:  added %i labels.\n", importLabelAddresses.size());
                    break;
                }
            }
        }
    }

    isAttaching = false;
}

std::string GetSymbolNameFromAddressDuringAttach(duint address)
{
    //DWORD64  dwDisplacement = 0;
    //DWORD64  dwAddress = address;

    //char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    //PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    //pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    //pSymbol->MaxNameLen = MAX_SYM_NAME;

    //if (SymFromAddr(hProcess, dwAddress, &dwDisplacement, pSymbol))
    //{
    //    // SymFromAddr returned success
    //    return std::string(pSymbol->Name);
    //}
    //else
    //{
    //    // SymFromAddr failed
    //    DWORD error = GetLastError();
    //    plog("SymFromAddr returned error : %d\n", error);
    //}

    return std::string();
}

std::string GetModuleNameFromAddressDuringAttach(duint address)
{
    static const DWORD moduleFlags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    char moduleName[MAX_MODULE_SIZE] = {0};
    HMODULE hModule = 0;

    if (!GetModuleHandleEx(moduleFlags, (LPCTSTR)address, &hModule))
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProcess, (PVOID)address, &mbi, sizeof(mbi)))
        {
            //plog("[" PLUGIN_NAME "]:  failed to get module name for %p.\n", address);
            return std::string();
        }
        hModule = (HMODULE)mbi.AllocationBase;
    }

    if (!GetModuleFileNameEx(hProcess, hModule, moduleName, MAX_MODULE_SIZE))
    {
        //plog("GetModuleNameFromAddress failed for %p,  %d.\n", address, GetLastError());
        return std::string();
    }

    PathStripPath(moduleName);
    PathRemoveExtension(moduleName);

    //plog("hModule = %x    %s.\n", hModule, moduleName);

    return std::string(moduleName);
}
