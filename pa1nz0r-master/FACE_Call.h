//FACE Importer (Special)
__declspec(noinline) PBYTE GetModBase(const char* ModuleName) {
	PPEB_LDR_DATA Ldr = ((PTEB)__readgsqword(FIELD_OFFSET(NT_TIB, Self)))->ProcessEnvironmentBlock->Ldr; void* ModBase = nullptr;
	for (PLIST_ENTRY CurEnt = Ldr->InMemoryOrderModuleList.Flink; CurEnt != &Ldr->InMemoryOrderModuleList; CurEnt = CurEnt->Flink) {
		LDR_DATA_TABLE_ENTRY_FIX* pEntry = CONTAINING_RECORD(CurEnt, LDR_DATA_TABLE_ENTRY_FIX, InMemoryOrderLinks);
		if (!ModuleName || StrCmp(ModuleName, pEntry->BaseDllName.Buffer, false)) return (PBYTE)pEntry->DllBase;
	} return nullptr;
}

//set (VMProtect - Funcs - Mutation)
__declspec(noinline) DWORD64 GetExportAddr(PVOID ModBase, const char* Name)
{
	//parse headers
	PIMAGE_NT_HEADERS NT_Head = (PIMAGE_NT_HEADERS)((DWORD64)ModBase + ((PIMAGE_DOS_HEADER)ModBase)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

	//process entrys
	for (DWORD i = 0; i < ExportDir->NumberOfNames; i++)
	{
		//get ordinal & name
		WORD Ordinal = ((uint16_t*)((DWORD64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)(DWORD64)ModBase + ((PDWORD)((DWORD64)ModBase + ExportDir->AddressOfNames))[i];

		//check export name
		if (StrCmp(Name, ExpName, true))
			return (DWORD64)ModBase + ((PDWORD)((DWORD64)ModBase + ExportDir->AddressOfFunctions))[Ordinal];
	} return 0;
}

//FACE Imp Call
#define FC(Mod, Name, ...) [&](){ \
	using _OVar = decltype(Name(__VA_ARGS__)); typedef _OVar(*_CFunc)(...); \
	return _CFunc(GetExportAddr(GetModBase(E(#Mod)), E(#Name)))(__VA_ARGS__); \
}()

#pragma section(".text")
__declspec(allocate(".text"))
const unsigned char syscallerStub[] = { 
	0x4C, 0x8B, 0x11, //mov    r10, QWORD PTR [rcx]
	0x8B, 0x41, 0x08, //mov    eax, DWORD PTR [rcx+0x8]
	0x0F, 0x05,       //syscall
	0xC3              //ret
};

//FACE SysCall v1
template <typename RetType = void, typename First = void*, typename... ArgsTypes>
__forceinline RetType SysCall(DWORD Index, First Arg1 = First{}, ArgsTypes... NextArgs) {
	struct DataStruct { First Arg1; DWORD SyscallID; } Data{ Arg1, Index };
	typedef RetType(__fastcall* CallStubFn)(DataStruct*, ArgsTypes...);
	return ((CallStubFn)&syscallerStub[0])(&Data, NextArgs...);
}