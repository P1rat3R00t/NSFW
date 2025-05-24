// mal_dll.cpp : Defines the exported functions for the DLL application.
//
#include "mal_dll.h"

// did not play in function, so it would be hard to reverse obfuscated API call
const char* szMessage = "Beware";
const char* szCaption = "Take action!";
INT(WINAPI *fFuncProc)(HWND, LPCSTR, LPCSTR, UINT);

void showMessage()
{
	fFuncProc = (INT(__stdcall *)(HWND, LPCSTR, LPCSTR, UINT))GetProcAddress(
		LoadLibrary("user32.dll"), 
		"MessageBoxA"
	);
	fFuncProc(0, szMessage, szCaption, 0);
}
