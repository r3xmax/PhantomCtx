#include <Windows.h>
#include <stdio.h>

#include "recon.h"
#include "..\common\dynamic_resolution.h"
#include "..\common\c_runtime.h"
#include "..\common\ntdefs.h"
#include "..\common\actctx.h"
#include "..\common\process_utils.h"

BOOL reconSpawn(const char* targetPath){

    // Dynamic module address resolution using custom implementation of GetModuleHandleW
    HMODULE hKernel32 = phantom_GetModuleHandleW(L"kernel32.dll");

    if(!hKernel32){
        printf("[ERROR] Couldn't get 'kernel32.dll' handle.\n");
        return FALSE;
    }

    HMODULE hNtdll = phantom_GetModuleHandleW(L"ntdll.dll");

    if(!hNtdll){
        printf("[ERROR] Couldn't get 'ntdll.dll' handle.\n");
        return FALSE;
    }

    // Dynamic function address resolution using custom implementation of GetProcAddressA
    fnCreateProcessW pCreateProcessW = (fnCreateProcessW)phantom_GetProcAddressA(hKernel32, "CreateProcessW");
    fnNtReadVirtualMemory pNtReadVirtualMemory = (fnNtReadVirtualMemory)phantom_GetProcAddressA(hNtdll, "NtReadVirtualMemory");
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)phantom_GetProcAddressA(hNtdll, "NtQueryInformationProcess");

    if(!pCreateProcessW || !pNtReadVirtualMemory || !pNtQueryInformationProcess){
        printf("[ERROR] Dynamic function address resolution failed.\n");
        return FALSE;
    }

    // Launch target process in suspended state
    WCHAR* widePath = phantom_char_to_wchar_ascii(targetPath);
    STARTUPINFOW si  = { 0 };
    si.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION pi = { 0 };

    BOOL result = pCreateProcessW(
        NULL,             
        widePath,         
        NULL,             
        NULL,             
        FALSE,            
        CREATE_SUSPENDED, 
        NULL,             
        NULL,             
        &si,              
        &pi               
    );

    free(widePath);
    
    if (!result) {
        printf("[ERROR] CreateProcessW failed: %u\n", GetLastError());
        return FALSE;
    }

    printf("[SUCCESS] Suspended process created...\n");

    // Copy ACTIVATION_CONTEXT_DATA blob from target process to local heap buffer
    SIZE_T actCtxSize = 0;
    void* actCtxBlob = CopyRemoteActCtxByHandle(pNtQueryInformationProcess, pNtReadVirtualMemory, pi.hProcess, &actCtxSize);

    if(!actCtxBlob){
        printf("[ERROR] Failed to copy Activation Context Data blob to local process buffer.\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Parse TOC entries and DLL redirection section from the Activation Context Data blob
    ParseDllRedirections((const BYTE*)actCtxBlob, (ULONG)actCtxSize);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, actCtxBlob);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

BOOL reconRuntime(const char* processName){

    // Dynamic module address resolution using custom implementation of GetModuleHandleW
    HMODULE hNtdll = phantom_GetModuleHandleW(L"ntdll.dll");

    if(!hNtdll){
        printf("[ERROR] Couldn't get 'ntdll.dll' handle.\n");
        return FALSE;
    }

    // Dynamic function address resolution using custom implementation of GetProcAddressA
    fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)phantom_GetProcAddressA(hNtdll, "NtQuerySystemInformation");
    fnNtOpenProcess pNtOpenProcess = (fnNtOpenProcess)phantom_GetProcAddressA(hNtdll, "NtOpenProcess");
    fnNtReadVirtualMemory pNtReadVirtualMemory = (fnNtReadVirtualMemory)phantom_GetProcAddressA(hNtdll, "NtReadVirtualMemory");
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)phantom_GetProcAddressA(hNtdll, "NtQueryInformationProcess");


    if(!pNtQuerySystemInformation || !pNtOpenProcess || !pNtReadVirtualMemory || !pNtQueryInformationProcess){
        printf("[ERROR] Dynamic function address resolution failed.\n");
        return FALSE;
    }

    // Get target process handle specifying the name
    WCHAR* ps_name = phantom_char_to_wchar_ascii(processName);
    HANDLE hProcess = GetProcessHandleByName(pNtQuerySystemInformation, pNtOpenProcess, ps_name, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
    
    if (!hProcess) {
        free(ps_name);
        return FALSE;
    }

    free(ps_name);

    // Copy ACTIVATION_CONTEXT_DATA blob from target process to local heap buffer
    SIZE_T actCtxSize = 0;
    void* actCtxBlob = CopyRemoteActCtxByHandle(pNtQueryInformationProcess, pNtReadVirtualMemory, hProcess, &actCtxSize);

    if(!actCtxBlob){
        printf("[ERROR] Failed to copy Activation Context Data blob to local process buffer.\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Parse TOC entries and DLL redirection section from the Activation Context Data blob
    ParseDllRedirections((const BYTE*)actCtxBlob, (ULONG)actCtxSize);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, actCtxBlob);
    CloseHandle(hProcess);
    return TRUE;
}

BOOL modeRecon(const char* submode, const char* target) {

    if (strcmp(submode, "spawn") == 0) {
        if(!reconSpawn(target)){
            return FALSE;
        }
        return TRUE;

    } else if (strcmp(submode, "runtime") == 0) {
        if(!reconRuntime(target)){
            return FALSE;
        }
        return TRUE;
    }

    return FALSE;
}