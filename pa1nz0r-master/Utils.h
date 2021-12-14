void GenRndStr(wchar_t* RndStr)
{
	int RndLen = (Rand() % 12) + 8;

	for (int i = 0; i < RndLen; i++)
	{
		switch (Rand() % 3)
		{
			case 0: {
				RndStr[i] = ((char)('A' + Rand() % 26));
			} break;

			case 1: {
				RndStr[i] = ((char)('a' + Rand() % 26));
			} break;

			case 2: {
				RndStr[i] = ((char)('0' + Rand() % 10));
			} break;
		}
	}

	RndStr[RndLen] = 0;
}

void TextPrint(const char* Str) {
	DWORD Bytes = StrLen(Str);
	HANDLE hConsole = FC(kernelbase, GetStdHandle, STD_OUTPUT_HANDLE);
	FC(kernel32, WriteConsoleA, hConsole, Str, Bytes, &Bytes, nullptr);
}

void PrintErr(const char* Msg, WORD Color = FOREGROUND_RED)
{
	CONSOLE_SCREEN_BUFFER_INFO ConsolePrev;
	HANDLE hConsole = FC(kernelbase, GetStdHandle, STD_OUTPUT_HANDLE);
	FC(kernel32, GetConsoleScreenBufferInfo, hConsole, &ConsolePrev);
	FC(kernel32, SetConsoleTextAttribute, hConsole, Color); TextPrint(Msg);
	FC(kernel32, SetConsoleTextAttribute, hConsole, ConsolePrev.wAttributes);
	FC(kernelbase, Sleep, 1800); FC(ntdll, RtlExitUserProcess, 0);
}

void PrepConsoleApp() {
	wchar_t Title[20]; GenRndStr(Title);
	auto AdwDll = xorstr(L"advapi32"); auto UserDll = xorstr(L"user32");
	FC(kernel32, SetConsoleTitleW, Title); TextPrint(E("DRV MEMEDrv v1\n\n"));
	FC(kernelbase, LoadLibraryExW, AdwDll.crypt_get(), nullptr, 0);
	FC(kernelbase, LoadLibraryExW, UserDll.crypt_get(), nullptr, 0);
}

const wchar_t* FindDrvPath()
{
	//get command-line args
	wchar_t* Cmd = FC(kernelbase, GetCommandLineW);
	int CmdLen = StrLen(Cmd) - 1; if (CmdLen == -1)
		return nullptr;

	//find driver path
	if (Cmd[CmdLen--] == '\"') {
		Cmd[CmdLen + 1] = 0;
		for (; CmdLen >= 0; CmdLen--) {
			if (Cmd[CmdLen] == '\"') {
				Cmd[CmdLen++] = 0;
				return &Cmd[CmdLen];
			}
		}
	}

	else {

		for (; CmdLen >= 0; CmdLen--) {
			if (Cmd[CmdLen] == ' ') {
				return &Cmd[++CmdLen];
			}
		}
	}

	//invalid arg
	return nullptr;
}

void LockConsole(bool Switch) {
	HWND Wnd = FC(kernel32, GetConsoleWindow);
	FC(user32, EnableWindow, Wnd, !Switch);
}

ParseStatus ParseFile(PIMAGE_NT_HEADERS& NT_Head, PVOID* DriverBytes)
{
	//try open file & get info
	PVOID ImageLocal = (PVOID)*DriverBytes; //if (ImageLocal) goto ParseHeaders; 
	const wchar_t* DrvPath = FindDrvPath(); if (DrvPath == nullptr) return BAD_CMD_LINE;
	HANDLE hFile = FC(kernelbase, CreateFileW, DrvPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return BAD_ACCESS_FILE; DWORD fSize = FC(kernelbase, GetFileSize, hFile, nullptr);
	if (fSize < 64 || fSize > 0x3200000) { FC(ntdll, NtClose, hFile); return BAD_FILE_SIZE; }

	//read file file
	ImageLocal = malloc1(fSize);
	FC(kernelbase, ReadFile, hFile, ImageLocal, fSize, (PDWORD)&fSize, nullptr);
	FC(ntdll, NtClose, hFile); goto ParseHeaders;

	//error nt
	mErrHeaders:
	free1(ImageLocal);
	return BAD_FILE;

	ParseHeaders: //parse image headers
	PIMAGE_DOS_HEADER DOS_Head = (PIMAGE_DOS_HEADER)ImageLocal;
	if (DOS_Head->e_magic != IMAGE_DOS_SIGNATURE) goto mErrHeaders;
	DWORD64 _NT_Head = ((DWORD64)ImageLocal + DOS_Head->e_lfanew);
	if (_NT_Head < (DWORD64)ImageLocal + 64 || _NT_Head + 264 >(DWORD64)ImageLocal + 4096)
		goto mErrHeaders;

	//check is 64bit driver
	if (((PIMAGE_NT_HEADERS)_NT_Head)->Signature != IMAGE_NT_SIGNATURE ||
		((PIMAGE_NT_HEADERS)_NT_Head)->OptionalHeader.Magic != 0x20B ||
		((PIMAGE_NT_HEADERS)_NT_Head)->OptionalHeader.Subsystem != 1)
		goto mErrHeaders;

	//cleanup headers & ret image base
	NT_Head = (PIMAGE_NT_HEADERS)_NT_Head;
	NT_Head->OptionalHeader.MajorLinkerVersion = 0;
	NT_Head->Signature = 0;	NT_Head->OptionalHeader.Magic = 0;
	MemZero(ImageLocal, (DWORD)(_NT_Head - (DWORD64)ImageLocal));
	*DriverBytes = ImageLocal; return FILE_OK;
}

DECLSPEC_NOINLINE //(VMProtect - Funcs - Mutation)
void DecrtBytes(PBYTE Buff, DWORD Size, PBYTE Out) {
	for (DWORD i = 0; i < Size; i++)
		Out[i] = (BYTE)(Buff[i] ^ ((i + 32 * i + 78) + 45 + i));
}

void CleanTrace() 
{
	auto ObfDereferenceObject = CPL0.Resolve(E("ObfDereferenceObject"));
	auto IoGetDeviceObjectPointer = CPL0.Resolve(E("IoGetDeviceObjectPointer"));
	auto RtlLookupElementGenericTableAvl = CPL0.Resolve(E("RtlLookupElementGenericTableAvl"));
	auto RtlDeleteElementGenericTableAvl = CPL0.Resolve(E("RtlDeleteElementGenericTableAvl"));

	PVOID pObject = nullptr, pFileObj = nullptr;
	auto DeviceStringCrt = xorstr(L"\\Device\\inpoutx64");
	UNICODE_STRING DeviceString = UNC_STR(DeviceStringCrt.size(), DeviceStringCrt.crypt_get());
	CPL0.CallInKernel<NTSTATUS>(IoGetDeviceObjectPointer, &DeviceString, FILE_ALL_ACCESS, &pFileObj, &pObject);
	CPL0.CallInKernel(ObfDereferenceObject, pFileObj);
	
	auto DriverObject = CPL0.ReadVA_T<PVOID>((ULONG64)pObject + 8);
	auto DriverSection = CPL0.ReadVA_T<PVOID>((ULONG64)DriverObject + 0x28);
	auto BaseDllName = CPL0.ReadVA_T<UNICODE_STRING>((ULONG64)DriverSection + 0x58);
	
	auto piddb = (PVOID)CPL0.FindPattern(E("48 8D 0D ? ? ? ? 45 8D 41 38 E8"));
	piddb = CPL0.RVA((ULONG64)piddb, 7);

	struct PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16];
	} PiDDB_Entry{};
	PiDDB_Entry.DriverName = BaseDllName;
	PiDDB_Entry.TimeDateStamp = 0x48f9193c;
	auto pFoundEntry = CPL0.CallInKernel<PiDDBCacheEntry*>(RtlLookupElementGenericTableAvl, piddb, &PiDDB_Entry);
	auto RemoveEntryList = [](PLIST_ENTRY Entry) {
		PLIST_ENTRY NextEntry = CPL0.ReadVA_T<PLIST_ENTRY>(Entry);
		PLIST_ENTRY PrevEntry = CPL0.ReadVA_T<PLIST_ENTRY>((ULONG64)Entry + 8);
		CPL0.WriteVA_T(PrevEntry, NextEntry);
		CPL0.WriteVA_T((ULONG64)NextEntry + 8, PrevEntry);
	};
	RemoveEntryList(&pFoundEntry->List);
	CPL0.CallInKernel(RtlDeleteElementGenericTableAvl, piddb, pFoundEntry);

	BaseDllName.Length = 0;
	auto zeroPtr = malloc1(BaseDllName.MaximumLength);
	CPL0.MemCpy(BaseDllName.Buffer, zeroPtr, BaseDllName.MaximumLength);
	CPL0.WriteVA_T<UNICODE_STRING>((ULONG64)DriverSection + 0x58, BaseDllName);
	free1(zeroPtr);
}