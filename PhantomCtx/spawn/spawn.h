#pragma once
#include <Windows.h>

BOOL modeSpawn(
    const char* submode,
    const char* targetPath,
    const char* dllName,
    const char* dllPath,
    const char* stealFrom
);

BOOL spawnStealContext(
    const char* targetPath,
    const char* dllName,
    const char* dllPath,
    const char* stealFrom
);

BOOL spawnAddEntry(
    const char* targetPath,
    const char* dllName,
    const char* dllPath
);

BOOL spawnPatchEntry(
    const char* targetPath,
    const char* dllName,
    const char* dllPath
);