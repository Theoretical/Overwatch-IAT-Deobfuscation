# Overwatch IAT Deobfuscation
author: &nbsp;&nbsp;&nbsp;&nbsp;qwerty9384

**summary:**

this plugin adds the **'oiu'** command to x64dbg.  the command locates the memory region containing Overwatch's import address table, deobfuscates all import entries, and labels each import's thunk address.

**how to use:**

1.  attach x64dbg to overwatch.exe.
2.  enter **'oiu'** in the command line.

**example output:**

```
[OW Imports]:  00000000002B0A50  actual = 0000000077843380  kernel32.GetCurrentThreadIdStub
[OW Imports]:  00000000002B0A66  actual = 00000000778348D0  kernel32.OutputDebugStringAStub
[OW Imports]:  00000000002B0A7C  actual = 0000000077845190  kernel32.GetCurrentProcessStub
[OW Imports]:  00000000002B0A92  actual = 0000000077976540  ntdll.RtlInitializeCriticalSection
[OW Imports]:  00000000002B0AA8  actual = 000000007799DA50  ntdll.RtlEnterCriticalSection
```

**contact:**

pm me @ unknowncheats.me if you have questions.
