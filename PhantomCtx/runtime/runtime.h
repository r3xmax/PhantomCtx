#pragma once
#include <Windows.h>

BOOL modeRuntime(
    const char* submode,
    const char* targetName,
    const char* dllName,
    const char* dllPath,
    const char* stealFrom
);

BOOL runtimeStealContext(
    const char* targetName,
    const char* dllName,
    const char* dllPath,
    const char* stealFrom
);

BOOL runtimeAddEntry(
    const char* targetName,
    const char* dllName,
    const char* dllPath
);

BOOL runtimePatchEntry(
    const char* targetName,
    const char* dllName,
    const char* dllPath
);
