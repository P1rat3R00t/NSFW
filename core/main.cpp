

#include "injection.h"

int main(int argc, char* argv[]) {

    PrintBanner();

    if (argc < 2) {
        WARN("usage: \"%s\" [PID]", argv[0]);
        return EXIT_FAILURE;
    }

    if (!DLLInjection(DLL, atoi(argv[1]), sizeof(DLL))) {
        WARN("DLL injection failed, exiting...");
        return EXIT_FAILURE;
    }

    OKAY("DLL injection was successful! exiting...");
    return EXIT_SUCCESS;

}
