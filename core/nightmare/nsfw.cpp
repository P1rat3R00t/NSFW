#include "pch.h"
#include <iostream>
#include <Windows.h>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);

// EXAMPLE ONLY: Replace with your actual in-memory payload or fetch method.
extern "C" unsigned char dllPayload[]; // Define this elsewhere
extern "C" size_t dllPayloadSize;

int main()
{
	LPVOID dllBytes = dllPayload;  // already in memory
	DWORD64 dllSize = dllPayloadSize;

	// Parse headers
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	// Allocate space for DLL image
	LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

	// Copy headers
	std::memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	// Copy sections
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		LPVOID dest = (LPVOID)((DWORD_PTR)dllBase + section->VirtualAddress);
		LPVOID src = (LPVOID)((DWORD_PTR)dllBytes + section->PointerToRawData);
		std::memcpy(dest, src, section->SizeOfRawData);
		section++;
	}

	// Relocations
	IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocDir.VirtualAddress + (DWORD_PTR)dllBase;
	DWORD relocProcessed = 0;

	while (relocProcessed < relocDir.Size) {
		PBASE_RELOCATION_BLOCK relocBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocProcessed);
		relocProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocCount = (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocProcessed);

		for (DWORD i = 0; i < relocCount; i++) {
			relocProcessed += sizeof(BASE_RELOCATION_ENTRY);
			if (relocEntries[i].Type == 0) continue;

			DWORD_PTR patchAddr = (DWORD_PTR)dllBase + relocBlock->PageAddress + relocEntries[i].Offset;
			DWORD_PTR patchedVal = 0;
			std::memcpy(&patchedVal, (PVOID)patchAddr, sizeof(DWORD_PTR));
			patchedVal += deltaImageBase;
			std::memcpy((PVOID)patchAddr, &patchedVal, sizeof(DWORD_PTR));
		}
	}

	// Resolve imports
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD_PTR)dllBase);

	while (importDesc->Name) {
		LPCSTR libName = (LPCSTR)((DWORD_PTR)dllBase + importDesc->Name);
		HMODULE lib = LoadLibraryA(libName);
		if (!lib) { importDesc++; continue; }

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDesc->FirstThunk);
		while (thunk->u1.AddressOfData) {
			FARPROC fnAddr = nullptr;
			if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
				fnAddr = GetProcAddress(lib, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
			} else {
				PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
				fnAddr = GetProcAddress(lib, import->Name);
			}
			thunk->u1.Function = (DWORD_PTR)fnAddr;
			++thunk;
		}
		importDesc++;
	}

	// Call entry point
	DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

	return 0;
}
