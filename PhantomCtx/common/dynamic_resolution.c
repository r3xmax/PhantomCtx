#include <Windows.h>
#include <winternl.h>
#include "c_runtime.h"

// Custom implementation of GetModuleHandleW
HMODULE phantom_GetModuleHandleW(IN LPCWSTR szModuleName) {
    // Indirect PEB access
    PTEB pTeb = (PTEB)_readgsbase_u64();
    PPEB pPeb = *(PPEB*)((BYTE*)pTeb + 0x60);
    PLDR_DATA_TABLE_ENTRY pDte      = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);
    PLIST_ENTRY           pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY           pListNode = (PLIST_ENTRY)pListHead->Flink;

    do {
        if (pDte->FullDllName.Length != 0) {

            // Extract filename from full path (find last backslash)
            WCHAR* fullName = pDte->FullDllName.Buffer;
            WCHAR* fileName = fullName;
            for (WCHAR* p = fullName; *p; p++) {
                if (*p == L'\\') fileName = p + 1;
            }

            // Case-insensitive compare against filename only
            if (phantom_lstrcmpiW(fileName, szModuleName) == 0) {
                return (HMODULE)(pDte->Reserved2[0]);
            }

            // Advance to next entry
            pDte      = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);
            pListNode = (PLIST_ENTRY)pListNode->Flink;
        }
    } while (pListNode != pListHead);

    return NULL;
}

// Custom implementation of GetProcAddressA
FARPROC phantom_GetProcAddressA(HMODULE hModule, LPCSTR lpProcName) {
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
  ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
  WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
  DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

  for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
    if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
      return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
    }
  }

  return NULL;
}