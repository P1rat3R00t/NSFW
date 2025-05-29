#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>

using namespace std;

const int BUFFER_SIZE = 4096;

int main(int argc, char* argv[]) {
    // Make sure a filename was provided as an argument
    if (argc < 2) {
        cerr << "Error: no file name provided" << endl;
        return 1;
    }

    // Open the file for reading
    ifstream file(argv[1], ios::binary);
    if (!file) {
        cerr << "Error: could not open file" << endl;
        return 1;
    }

    // Calculate the hash of the file
    unsigned char buffer[BUFFER_SIZE];
    size_t length;
    unsigned long long hash = 0;
    while ((length = file.readsome((char*)buffer, BUFFER_SIZE)) > 0) {
        for (size_t i = 0; i < length; i++) {
            hash = (hash * 131) + buffer[i];
        }
    }

    // Print the hash to the console
    cout << hash << endl;

    return 0;
}
