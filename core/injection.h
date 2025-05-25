
#pragma once
#include <windows.h>
#include <stdio.h>

#define DLL L"dll\\crow.dll"
#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME)                                   \
    do {                                                             \
        fprintf(stderr,                                              \
                "[!] [" FUNCTION_NAME "] failed, error: 0x%lx\n"     \
                "[*] %s:%d\n", GetLastError(), __FILE__, __LINE__);  \
    } while (0)


BOOL DLLInjection(
    _In_ LPCWSTR DLLPath,
    _In_ CONST DWORD PID,
    _In_ CONST SIZE_T PathSize
);


VOID PrintBanner(VOID);
