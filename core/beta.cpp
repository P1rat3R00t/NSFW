// DataWiperDll.cpp
// Windows 11-compatible C++ DLL template for data wiping
// For educational and security research purposes only!

#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "Shlwapi.lib")

// Exported function for external use
extern "C" __declspec(dllexport) BOOL WipeData(const wchar_t* targetPath, int passes);

// Helper: Overwrite a file securely
bool SecureWipeFile(const std::wstring& filePath, int passes) {
    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    size_t length = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(length);
    for (int p = 0; p < passes; ++p) {
        // Fill buffer with random data
        for (size_t i = 0; i < buffer.size(); ++i) buffer[i] = rand() % 256;
        file.seekp(0);
        file.write(buffer.data(), buffer.size());
        file.flush();
        file.seekp(0);
    }
    file.close();
    // Remove file after overwrite
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
    // Placeholder: Implement with CreateFile (\\.\C:), DeviceIoControl, etc.
    // WARNING: This is extremely dangerous and can brick the OS!
    return false;
}

// DLL Export: Main entry point for wiper
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

// DLL entry point (not used for auto-execution)
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
