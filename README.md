# LsassUnhooker
Little program written in C# to bypass EDR hooks and dump the content of the lsass process. The code makes use of [SharpUnhooker](https://github.com/GetRektBoy724/SharpUnhooker).

This project, created by GetRektBoy724, works the following way:

1.  It reads and copies the `.text section` of the original (in-disk) DLL using "PE parser stuff"
2.  It patches the `.text section` of the loaded DLL using `Marshal.Copy` and `NtProtectVirtualMemory` from D/Invoke (to changes the permission of the memory)
3.  It checks the patched in-memory DLL by reading it again and compare it with the original one to see if its correctly patched.
