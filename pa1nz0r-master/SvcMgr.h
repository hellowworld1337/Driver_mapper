#include "Bytes.h"

void SwLoadDrvPriv(bool Enable)
{
	//get privilege id
	TOKEN_PRIVILEGES Privilege; MemZero(&Privilege, sizeof(Privilege));
	auto PrivNameCrt = xorstr("SeLoadDriverPrivilege"); HANDLE hToken;
	const char* PrivName = PrivNameCrt.crypt_get(); Privilege.PrivilegeCount = 1;
	FC(advapi32, LookupPrivilegeValueA, nullptr, PrivName, &Privilege.Privileges[0].Luid);

	//switch privilege
	FC(advapi32, OpenProcessToken, (HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (Enable) Privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	FC(advapi32, AdjustTokenPrivileges, hToken, false, &Privilege, sizeof(Privilege), nullptr, nullptr);
	FC(ntdll, NtClose, hToken);
}

bool SvcMgr(const wchar_t* NameW, bool Install)
{
	//get file path
	wchar_t FileRegPath[MAX_PATH]; FileRegPath[0] = 0; wchar_t* FilePath = &FileRegPath[4];
	StrCat(FileRegPath, E(L"\\??\\")); FC(kernel32, GetTempPathW, MAX_PATH - 4, FilePath); 
	StrCat(FilePath, NameW); StrCat(FilePath, E(L".log"));

	//lock console & create reg entry
	HKEY Key1, Key2; DWORD Type = 1; if (Install) LockConsole(true);
	auto SvcPathCrt = xorstr("system\\CurrentControlSet\\Services"); auto ImgPathCrt = xorstr(L"ImagePath"); auto TypeCrt = xorstr("Type");
	FC(advapi32, RegOpenKeyA, HKEY_LOCAL_MACHINE, SvcPathCrt.crypt_get(), &Key1); FC(advapi32, RegCreateKeyW, Key1, NameW, &Key2);
	FC(kernel32, RegSetValueExW, Key2, ImgPathCrt.crypt_get(), 0, REG_EXPAND_SZ, (const BYTE*)FileRegPath, ((StrLen(FileRegPath) + 1) << 1));
	FC(kernel32, RegSetValueExA, Key2, TypeCrt.crypt_get(), 0, REG_DWORD, (const BYTE*)&Type, 4); FC(kernel32, RegCloseKey, Key2);
	
	//gen service reg path
	wchar_t SvcRegPath[80]; SvcRegPath[0] = 0; UNICODE_STRING DevNT;
	StrCat(SvcRegPath, E(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\")); StrCat(SvcRegPath, NameW);
	DevNT.Length = USHORT(StrLen(SvcRegPath) << 1); DevNT.Buffer = SvcRegPath; DevNT.MaximumLength = DevNT.Length + 2;
	
	//load drv
	NTSTATUS Stat;
	if (Install)
	{
		//write file to disk
		FC(kernel32, MoveFileExW, FilePath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
		HANDLE hFile = FC(kernelbase, CreateFileW, FilePath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
		DecrtBytes(ExpDrv64, sizeof(ExpDrv64), ExpDrv64);
		FC(kernelbase, WriteFile, hFile, ExpDrv64, sizeof(ExpDrv64), &Type, nullptr);
		FC(ntdll, NtClose, hFile); MemZero(ExpDrv64, sizeof(ExpDrv64));

		//load driver
		SwLoadDrvPriv(true);
		Stat = FC(ntdll, NtLoadDriver, &DevNT);
		SwLoadDrvPriv(false);
	}

	//unload
	else {
		SwLoadDrvPriv(true);
		Stat = FC(ntdll, NtUnloadDriver, &DevNT);
		SwLoadDrvPriv(false);
	}

	//cleanup & ret driver status
	FC(kernelbase, DeleteFileW, FilePath);
	FC(advapi32, RegDeleteKeyW, Key1, NameW);
	FC(kernel32, RegCloseKey, Key1);
	if (!Install) LockConsole(false);
	return NT_SUCCESS(Stat);
}