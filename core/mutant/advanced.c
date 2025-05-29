
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// Structure for the poly engine
typedef struct {
    unsigned char key[16];
    size_t size;
    unsigned char data[256];
    void (*payload)(void);  // Function pointer for payload
} PolyEngine;



void dummyPayload(void) {
    printf("Dummy payload executed!\n");
}


void initPolyEngine(PolyEngine* pe) {
    // Generate a random key
    for (int i = 0; i < sizeof(pe->key); i++) {
        pe->key[i] = (unsigned char)(rand() % 256);
    }
    // Generate a random size for data (1-256)
    pe->size = (rand() % 256) + 1; // Ensure at least one byte
    pe->payload = dummyPayload;
}


void generatePoly(PolyEngine* pe) {
    // Randomly generate data
    for (size_t i = 0; i < pe->size; i++) {
        pe->data[i] = (unsigned char)(rand() % 256);
    }
}

void encryptPayload(PolyEngine* pe) {
    unsigned char* payloadBytes = (unsigned char*)&pe->payload;
    for (size_t i = 0; i < sizeof(void*); i++) {
        payloadBytes[i] ^= pe->key[i % sizeof(pe->key)];
    }
}


void decryptPayload(PolyEngine* pe) {
    unsigned char* payloadBytes = (unsigned char*)&pe->payload;
    for (size_t i = 0; i < sizeof(void*); i++) {
        payloadBytes[i] ^= pe->key[i % sizeof(pe->key)];
    }
}


void modifyData(PolyEngine* pe) {
    for (size_t i = 0; i < pe->size; i++) {
        switch(rand() % 4) {
            case 0:
                pe->data[i] ^= pe->key[i % sizeof(pe->key)]; // XOR
                break;
            case 1:
                pe->data[i] += (unsigned char)(rand() % 10); // Addition
                break;
            case 2:
                pe->data[i] = ~pe->data[i]; // NOT operation
                break;
            case 3:
                pe->data[i] = (pe->data[i] << 4) | (pe->data[i] >> 4); // Rotate
                break;
        }
    }
}


void saveData(const char* filename, PolyEngine* pe) {
    FILE* file = fopen(filename, "wb");
    if (file) {
        fwrite(&pe->payload, sizeof(void*), 1, file); // Write encrypted payload pointer
        fwrite(pe->key, sizeof(pe->key), 1, file); // Write the key
        fwrite(&pe->size, sizeof(pe->size), 1, file); // Write the size
        fwrite(pe->data, 1, pe->size, file); // Write the data
        fclose(file);
    } else {
        perror("Failed to open file");
    }
}

void loadAndExecute(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file) {
        PolyEngine loadedPe;
        // Read the encrypted payload pointer from the file
        fread(&loadedPe.payload, sizeof(void*), 1, file);
        // Read the encryption key from the file
        fread(loadedPe.key, sizeof(loadedPe.key), 1, file);
        // Read the size of the data from the file
        fread(&loadedPe.size, sizeof(loadedPe.size), 1, file);
        // Read the actual data from the file based on the size
        fread(loadedPe.data, 1, loadedPe.size, file);
        // Close the file after reading
        fclose(file);

        // Decrypt the payload
        decryptPayload(&loadedPe);
        
        // Execute the payload
        loadedPe.payload();
    } else {
        perror("Failed to open file for execution");
    }
}


int main() {
    srand(time(NULL) ^ getpid()); // Seed for random number generation
    PolyEngine pe;
    initPolyEngine(&pe);
    generatePoly(&pe);
    modifyData(&pe);
    
    // Encrypt the payload before saving
    encryptPayload(&pe);
    
    saveData("output.bin", &pe);
    printf("Data saved successfully!\n");
    
    // Load and execute
    loadAndExecute("output.bin");
    
    return 0;
}
