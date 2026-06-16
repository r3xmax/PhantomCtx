#pragma once
#include <Windows.h>

HMODULE phantom_GetModuleHandleW(
    LPCWSTR szModuleName
);

FARPROC phantom_GetProcAddressA(
    HMODULE hModule,
    LPCSTR lpProcName
);
