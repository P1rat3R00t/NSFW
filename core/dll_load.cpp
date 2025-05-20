#include <windows.h>
#include <iostream>
#include <string>

int main() {
    // Path to the DLL to load
    std::string dllPath = "../core/bin/nsfw.dll";

    // Load the DLL
    HMODULE hDll = LoadLibraryA(dllPath.c_str());
    if (!hDll) {
        std::cerr << "Failed to load DLL: " << dllPath << std::endl;
        return 1;
    }
    std::cout << "DLL loaded successfully!" << std::endl;

    // Example: Get the address of an exported function (e.g., "Dskcryptor_SecureWipeHandle")
    typedef BOOL (*WipeHandleFunc)(HANDLE);
    WipeHandleFunc wipeFunc = (WipeHandleFunc)GetProcAddress(hDll, "Dskcryptor_SecureWipeHandle");
    if (!wipeFunc) {
        std::cerr << "Failed to find Dskcryptor_SecureWipeHandle in DLL." << std::endl;
        FreeLibrary(hDll);
        return 1;
    }

    // Example usage: (HANDLE) -1 is INVALID_HANDLE_VALUE, just for demonstration
    BOOL result = wipeFunc(INVALID_HANDLE_VALUE);
    std::cout << "Dskcryptor_SecureWipeHandle returned: " << result << std::endl;

    // Free the DLL module
    FreeLibrary(hDll);
    std::cout << "DLL unloaded." << std::endl;

    return 0;
}
