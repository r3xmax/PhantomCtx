#pragma once
#include <Windows.h>

BOOL modeRecon(
    const char* submode,
    const char* target
);

BOOL reconSpawn(
    const char* targetPath
);

BOOL reconRuntime(
    const char* processName
);