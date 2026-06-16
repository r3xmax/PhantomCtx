#pragma once
#include <Windows.h>
#include <winternl.h>

/************************* Defines *************************/

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define PCLIENT_ID CLIENT_ID*

/* Activation Context related */
#define ACTX_MAGIC              0x78746341UL  /* "Actx" */
#define STRING_SECTION_MAGIC    0x64487353UL  /* "SsHd" */

#ifndef ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION
#define ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION    2
#endif

#ifndef ACTIVATION_CONTEXT_SECTION_FORMAT_STRING_TABLE
#define ACTIVATION_CONTEXT_SECTION_FORMAT_STRING_TABLE 1
#endif

// Manifest DLL Redirection flags
#define ACTX_DLL_REDIR_PATH_INCLUDES_BASE_NAME        0x00000001
#define ACTX_DLL_REDIR_OMITS_ASSEMBLY_ROOT            0x00000002
#define ACTX_DLL_REDIR_EXPAND                         0x00000004
#define ACTX_DLL_REDIR_SYSTEM_DEFAULT_REDIRECTED      0x00000008

// Given a Activation Context blob base pointer and a byte offset, returns a pointer of type T (specified by user).
// Avoids repeating the (T*)((BYTE*)(base) + offset) pattern everywhere.
#define BLOB_PTR(base, offset, T) \
    ((T*)((BYTE*)(base) + (offset)))

/************************* Enums *************************/

typedef enum _SECTION_INHERIT
{
    ViewShare = 1, // The mapped view of the section will be mapped into any child processes created by the process.
    ViewUnmap = 2  // The mapped view of the section will not be mapped into any child processes created by the process.
} SECTION_INHERIT;

/************************* Structs *************************/

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ACTIVATION_CONTEXT_DATA_TOC_HEADER {
    ULONG HeaderSize;
    ULONG EntryCount;
    ULONG FirstEntryOffset;   // from B0
    ULONG Flags;
} ACTIVATION_CONTEXT_DATA_TOC_HEADER;

typedef struct _ACTIVATION_CONTEXT_DATA_TOC_ENTRY {
    ULONG Id;
    ULONG Offset;             // from B0
    ULONG Length;
    ULONG Format;
} ACTIVATION_CONTEXT_DATA_TOC_ENTRY;

typedef struct _ACTIVATION_CONTEXT_STRING_SECTION_HEADER {
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG DataFormatVersion;
    ULONG Flags;
    ULONG ElementCount;
    ULONG ElementListOffset;        // from B1
    ULONG HashAlgorithm;
    ULONG SearchStructureOffset;    // from B1
    ULONG UserDataOffset;           // from B1
    ULONG UserDataSize;
} ACTIVATION_CONTEXT_STRING_SECTION_HEADER;

typedef struct _ACTIVATION_CONTEXT_STRING_SECTION_ENTRY {
    ULONG PseudoKey;
    ULONG KeyOffset;          // from B1
    ULONG KeyLength;          // in bytes
    ULONG Offset;             // from B1
    ULONG Length;
    ULONG AssemblyRosterIndex;
} ACTIVATION_CONTEXT_STRING_SECTION_ENTRY;

typedef struct _ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION {
    ULONG Size;
    ULONG Flags;
    ULONG TotalPathLength;    // in bytes
    ULONG PathSegmentCount;
    ULONG PathSegmentOffset;  // from B1
} ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION;

typedef struct _ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT {
    ULONG Length;             // in bytes
    ULONG Offset;             // from B1
} ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT;


/************************* NT Function Typedefs *************************/

// CreateProcessW from kernel32.dll
typedef BOOL (*fnCreateProcessW)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

// ResumeThread from kernel32.dll
typedef DWORD (*fnResumeThread)(
  HANDLE hThread
);

// NtQueryInformationProcess
typedef NTSTATUS (*fnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

// NtReadVirtualMemory
typedef NTSTATUS (*fnNtReadVirtualMemory)(
    HANDLE           ProcessHandle,
    PVOID            BaseAddress,
    PVOID            Buffer,
    SIZE_T           NumberOfBytesToRead,
    PSIZE_T          NumberOfBytesRead
);

// NtQuerySystemInformation
typedef NTSTATUS (*fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

// NtOpenProcess
typedef NTSTATUS (*fnNtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

// NtCreateSection
typedef NTSTATUS (*fnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

// NtMapViewOfSection
typedef NTSTATUS (*fnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG PageProtection
);

// NtUnmapViewOfSection
typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(
    _In_     HANDLE  ProcessHandle,
    _In_opt_ PVOID   BaseAddress
);