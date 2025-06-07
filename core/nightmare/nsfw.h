#ifndef NSFW_H
#define NSFW_H

#include <windows.h>
#include <ntdef.h>
#include "defines.h"

// Forward declarations of structs used
typedef struct wipe_ctx wipe_ctx;
typedef struct wipe_mode wipe_mode;

// Function declarations
#ifdef __cplusplus
extern "C" {
#endif

int dc_wipe_init(wipe_ctx *ctx, void *hook, int max_size, int method, int cipher);
void dc_wipe_free(wipe_ctx *ctx);
int dc_wipe_process(wipe_ctx *ctx, u64 offset, int size);

// DLL Entry Point
NTSTATUS NTAPI DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// Exported wiping function
__declspec(dllexport) BOOL WipeData(LPCWSTR targetPath, int passes);

#ifdef __cplusplus
}
#endif

#endif // NSFW_H
