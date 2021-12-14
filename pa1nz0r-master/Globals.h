#include <Windows.h>
#include <winternl.h>
#include <iostream>

//structs
typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef union _pte
{
	std::uint64_t value;
	struct
	{
		std::uint64_t present : 1;          // Must be 1, region invalid if 0.
		std::uint64_t rw : 1;               // If 0, writes not allowed.
		std::uint64_t user_supervisor : 1;  // If 0, user-mode accesses not allowed.
		std::uint64_t page_write : 1;        // Determines the memory type used to access the memory.
		std::uint64_t page_cache : 1;       // Determines the memory type used to access the memory.
		std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
		std::uint64_t dirty : 1;             // If 0, the memory backing this page has not been written to.
		std::uint64_t page_access_type : 1;  // Determines the memory type used to access the memory.
		std::uint64_t global : 1;            // If 1 and the PGE bit of CR4 is set, translations are global.
		std::uint64_t ignored2 : 3;
		std::uint64_t pfn : 36;             // The page frame number of the backing physical page.
		std::uint64_t reserved : 4;
		std::uint64_t ignored3 : 7;
		std::uint64_t protect_key : 4;       // If the PKE bit of CR4 is set, determines the protection key.
		std::uint64_t nx : 1;               // If 1, instruction fetches not allowed.
	};
} pte, *ppte;

struct LDR_DATA_TABLE_ENTRY_FIX {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	PVOID Reserved5[2];
#pragma warning(push)
#pragma warning(disable: 4201)
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
};

//defs
#define RtlImageNtHeader(Mod) ((PIMAGE_NT_HEADERS)((PBYTE)Mod + ((PIMAGE_DOS_HEADER)Mod)->e_lfanew))

#define UNC_STR(a, b) { USHORT(a * 2), USHORT((a + 1) * 2), (PWSTR)(b) }

#define SizeAlign(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

//funcs
BOOLEAN RtlFreeHeap(PVOID, ULONG, PVOID);
VOID RtlExitUserProcess(NTSTATUS);
NTSTATUS NtLoadDriver(PUNICODE_STRING);
NTSTATUS NtUnloadDriver(PUNICODE_STRING);
PVOID RtlAllocateHeap(PVOID, ULONG, ULONG);
PVOID NtQueryAuxiliaryCounterFrequency(PVOID, DWORD64, DWORD64, PVOID);

//prog defs
enum ParseStatus {
	FILE_OK,
	BAD_FILE,
	BAD_CMD_LINE,
	BAD_FILE_SIZE,
	BAD_ACCESS_FILE
};

//add headers
#include "StrCrypt.h"
#include "FACE_CRT.h"
#include "FACE_Call.h"

//heap alloc free
__forceinline PVOID malloc1(ULONG64 Size) {
	auto heap_handle = FC(kernel32, GetProcessHeap);
	return FC(ntdll, RtlAllocateHeap, heap_handle, HEAP_ZERO_MEMORY, Size);
}

__forceinline void free1(PVOID Ptr) {
	auto heap_handle = FC(kernel32, GetProcessHeap);
	FC(ntdll, RtlFreeHeap, heap_handle, 0, Ptr);
}

#include "PDB_Parser.h"
#include "InpOut_SDK.h"
#include "CPL0_Mgr.h"
#include "Utils.h"
#include "SvcMgr.h"