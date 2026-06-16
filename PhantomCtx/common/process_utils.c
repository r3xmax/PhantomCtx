#include <Windows.h>
#include <stdio.h>

#include "c_runtime.h"
#include "process_utils.h"
#include "ntdefs.h"

// Opens a handle to a process by PID with the specified access rights
HANDLE GetProcessHandleByPid(fnNtOpenProcess pNtOpenProcess, DWORD pid, ACCESS_MASK desiredAccess){
    
    NTSTATUS status = 0;

    // Process Info
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objPsAttr;
    InitializeObjectAttributes(&objPsAttr, NULL, 0, NULL, NULL);
    CLIENT_ID clientId = {(HANDLE)(ULONG_PTR)pid, (HANDLE)0};

    // Get Remote Process Handle
    status = pNtOpenProcess(&hProcess, desiredAccess, &objPsAttr, &clientId);

    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtOpenProcess failed. Status: 0x%08lX\n", (unsigned long)status);
        return NULL;
    }

    printf("[SUCCESS] Opened handle to PID %u\n", pid);

    return hProcess;
}

// Finds a process by name in the system process list and returns a handle with the specified access rights
HANDLE GetProcessHandleByName(
    fnNtQuerySystemInformation  pNtQuerySystemInformation,
    fnNtOpenProcess             pNtOpenProcess,
    const WCHAR*                ps_name,
    ACCESS_MASK                 desiredAccess
){
    NTSTATUS status = 0;

    // NtQuerySystemInformation required vars
    DWORD pid = 0;
    void* outbuffer = NULL;
    ULONG outbuff_size = 0;

    // Find out required buffer size
    pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &outbuff_size);

    // Allocate output buffer memory and call the function again
    outbuffer = malloc(outbuff_size);
    pNtQuerySystemInformation(SystemProcessInformation, outbuffer, outbuff_size, &outbuff_size);

    PSYSTEM_PROCESS_INFORMATION spi = outbuffer;

    // Walk process list and match by ImageName
    while (1) {
        if (spi->ImageName.Buffer != NULL &&
            phantom_lstrcmpiW(spi->ImageName.Buffer, ps_name) == 0) {
            pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
            break;
        }
        if (spi->NextEntryOffset == 0)
            break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
    }

    free(outbuffer);

    if(!pid){
        printf("[ERROR] Couldn't identify PID for process '%ls'\n", ps_name);
        return (HANDLE)0;
    }

    printf("[SUCCESS] Found '%ls' PID %lu\n", ps_name, pid);

    // Delegate handle opening to GetProcessHandleByPid
    HANDLE hProcess = GetProcessHandleByPid(pNtOpenProcess, pid, desiredAccess);

    if (!hProcess) {
        printf("[ERROR] Couldn't get process handle for '%ls'\n", ps_name);
        return (HANDLE)0;
    }

    return hProcess;
}