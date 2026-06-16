#pragma once
#include <Windows.h>
#include "ntdefs.h"

#define EXTRA_BYTES     512   // extra space for PatchDllRedirectionEntry
#define EXTRA_BYTES_ADD 1024  // extra space for AddDllRedirectionEntry

void* CopyRemoteActCtxByHandle(
    fnNtQueryInformationProcess pNtQueryInformationProcess,
    fnNtReadVirtualMemory pNtReadVirtualMemory,
    HANDLE hProcess,
    PSIZE_T actCtxSize
);

static int bounds_ok(
    const BYTE* blob,
    ULONG totalSize,
    ULONG offset,
    ULONG size
);

static void print_wcs(
    const WCHAR* ws,
    ULONG byteLen
);

static WCHAR* assemble_path(
    const BYTE* B1,
    ULONG b1Offset,
    const ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION* redir,
    ULONG totalSize
);

void ParseDllRedirections(
    const BYTE* blob,
    ULONG totalSize
);

ULONG PatchDllRedirectionEntry(
    BYTE*        blob,
    ULONG        totalSize,
    ULONG        entryIdx,
    const WCHAR* redirectPath
);

ULONG AddDllRedirectionEntry(
    BYTE*        blob,
    ULONG        totalSize,
    const WCHAR* dllName,
    const WCHAR* redirectPath,
    ULONG        rosterIdx
);

ULONG PatchOrAddDllRedirection(
    BYTE*        blob,
    ULONG        totalSize,
    const WCHAR* dllName,
    const WCHAR* redirectPath,
    ULONG        rosterIdx
);

NTSTATUS HijackActCtx(
    fnNtReadVirtualMemory         pNtReadVirtualMemory,
    fnNtCreateSection             pNtCreateSection,
    fnNtMapViewOfSection          pNtMapViewOfSection,
    fnNtUnmapViewOfSection        pNtUnmapViewOfSection,
    fnNtQueryInformationProcess   pNtQueryInformationProcess,
    HANDLE                        hProcess,
    void*                         actCtxBlob,
    SIZE_T                        actCtxSize
);