#pragma once
#include <Windows.h>
#include "ntdefs.h"

HANDLE GetProcessHandleByPid(
    fnNtOpenProcess pNtOpenProcess,
    DWORD pid,
    ACCESS_MASK desiredAccess
);

HANDLE GetProcessHandleByName(
    fnNtQuerySystemInformation  pNtQuerySystemInformation,
    fnNtOpenProcess             pNtOpenProcess,
    const WCHAR*                targetName,
    ACCESS_MASK                 desiredAccess
);