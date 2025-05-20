#pragma once
#ifndef DATA_WIPE_H
#define DATA_WIPE_H

#include <cstdint>
#include <vector>

enum class PassType {
    PATTERN,
    RANDOM
};

struct WipePass {
    PassType type;
    uint8_t pattern[3];
};

class WipeMode {
public:
    WipeMode(const std::vector<WipePass>& passes);
    const std::vector<WipePass>& getPasses() const;

private:
    std::vector<WipePass> passes_;
};

class WipeContext {
public:
    WipeContext(void* hook, size_t maxSize, const WipeMode& mode);
    ~WipeContext();

    bool initialize();
    void cleanup();
    int process(uint64_t offset, size_t size);

private:
    void* hook_;
    size_t maxSize_;
    WipeMode mode_;
    uint8_t* buffer_;
    // Add other necessary members
};

#endif // DATA_WIPE_H
