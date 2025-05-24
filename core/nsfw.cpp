// DataWiperDll.cpp
// Unified secure file/data wiper DLL with local + network support
// Educational & red team simulation purposes only

#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <lm.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Netapi32.lib")

// Exported function for external use (legacy local wipe)
extern "C" __declspec(dllexport) BOOL WipeData(const wchar_t* targetPath, int passes);

// Extended version: includes network share wiping, logging, fallback overwrite
extern "C" __declspec(dllexport) BOOL WipeDataExtended(const wchar_t* targetPath, int passes);

// ------------------ Core Wipe Logic ------------------ //

// Helper: Overwrite a file securely
bool SecureWipeFile(const std::wstring& filePath, int passes) {
    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    size_t length = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(length);
    for (int p = 0; p < passes; ++p) {
        for (size_t i = 0; i < buffer.size(); ++i) buffer[i] = rand() % 256;
        file.seekp(0);
        file.write(buffer.data(), buffer.size());
        file.flush();
        file.seekp(0);
    }
    file.close();
    return DeleteFileW(filePath.c_str());
}

// Helper: Wipe all files in a directory recursively
void WipeDirectory(const std::wstring& dirPath, int passes) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            SecureWipeFile(entry.path().wstring(), passes);
        }
    }
}

// Helper: (Optional) Wipe raw drive sectors (requires admin, dangerous!)
bool WipeDriveRaw(const wchar_t* driveLetter, int passes) {
    return false; // Stub - not implemented
}

// ------------------ Enhancements ------------------ //

// Check for UNC or mapped network path
bool IsNetworkPath(const std::wstring& path) {
    return PathIsNetworkPathW(path.c_str());
}

// Log wiped file names to temp directory
void LogWipedFile(const std::wstring& filePath) {
    std::wofstream logFile(L"C:\\Windows\\Temp\\wiperlog.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << L"[WIPED] " << filePath << std::endl;
        logFile.close();
    }
}

// Fallback: simulate memory overwrite when file is locked
bool TryMemoryOverwriteFallback(const std::wstring& filePath, int passes) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    size_t length = file.tellg();
    file.close();

    std::vector<char> dummy(length);
    for (int i = 0; i < passes; ++i) {
        for (size_t j = 0; j < dummy.size(); ++j)
            dummy[j] = rand() % 256;
        // Simulate memory overwrite
    }
    return true;
}

// Wipe with logging + fallback overwrite
bool SecureWipeFileExtended(const std::wstring& filePath, int passes) {
    if (SecureWipeFile(filePath, passes)) {
        LogWipedFile(filePath);
        return true;
    } else {
        TryMemoryOverwriteFallback(filePath, passes);
        return false;
    }
}

// Recursively wipe network-shared paths
void WipeNetworkPath(const std::wstring& networkPath, int passes) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(networkPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            SecureWipeFileExtended(entry.path().wstring(), passes);
        }
    }
}

// ------------------ DLL Entry + Exports ------------------ //

// Standard local wipe API
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

// Extended API: includes network path support and logging
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

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
