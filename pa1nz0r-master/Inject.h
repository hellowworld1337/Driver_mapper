void* RVA_VA(uintptr_t RVA, PIMAGE_NT_HEADERS NT_Head, void* LocalImg)
{
	PIMAGE_SECTION_HEADER pFirstSect = IMAGE_FIRST_SECTION(NT_Head);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSect; pSection < pFirstSect + NT_Head->FileHeader.NumberOfSections; pSection++)
		if (RVA >= pSection->VirtualAddress && RVA < pSection->VirtualAddress + pSection->Misc.VirtualSize)
			return (PUCHAR)LocalImg + pSection->PointerToRawData + RVA - pSection->VirtualAddress;
	return nullptr;
}

void RelocateImage(PIMAGE_NT_HEADERS NT_Head, uintptr_t RemoteImg, void* LocalImg)
{
	//get & check & parse relocation data
	intptr_t DeltaOffset = RemoteImg - NT_Head->OptionalHeader.ImageBase; if (!DeltaOffset) return;
	typedef struct _RelocEntry { uint32_t RVA; uint32_t Size; struct { uint16_t Offset : 12; uint16_t Type : 4; } Item[1]; } *pRelocEntry;
	pRelocEntry RelocEnt = (pRelocEntry)RVA_VA(NT_Head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, NT_Head, LocalImg);
	uintptr_t RelocEnd = (uintptr_t)RelocEnt + NT_Head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (!RelocEnt || !NT_Head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

	//process reloc table
	while ((uintptr_t)RelocEnt < RelocEnd && RelocEnt->Size)
	{
		//get records count & fix relocs
		uint32_t RecordsCount = (RelocEnt->Size - 8) >> 1;
		for (uint32_t i = 0; i < RecordsCount; i++)
		{
			//get fixup type & shift delta
			uint16_t FixType = RelocEnt->Item[i].Type;
			uint16_t ShiftDelta = (RelocEnt->Item[i].Offset) % 4096;

			//no relocate
			if (FixType == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			//select type relocation
			if (FixType == IMAGE_REL_BASED_HIGHLOW || FixType == IMAGE_REL_BASED_DIR64)
			{
				//check fixup in section & set offset 
				uintptr_t FixVA = (uintptr_t)RVA_VA(RelocEnt->RVA, NT_Head, LocalImg);
				if (!FixVA) continue; *(uintptr_t*)(FixVA + ShiftDelta) += DeltaOffset;
			}
		}

		//goto next reloc block
		RelocEnt = (pRelocEntry)((PUCHAR)RelocEnt + RelocEnt->Size);
	}
}

bool ResolveImport(void* LocalImg, PIMAGE_NT_HEADERS NT_Head)
{
	//get import data & check valid
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVA_VA(
		NT_Head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, NT_Head, LocalImg);
	if (!ImportDesc || !NT_Head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return true;

	//process modules
	LPSTR ModuleName = nullptr;
	while ((ModuleName = (LPSTR)RVA_VA(ImportDesc->Name, NT_Head, LocalImg)))
	{
		//zero set (import module name)
		MemZero(ModuleName, StrLen(ModuleName));

		//process entries
		PIMAGE_THUNK_DATA IHData = (PIMAGE_THUNK_DATA)RVA_VA(ImportDesc->FirstThunk, NT_Head, LocalImg);
		while (IHData->u1.AddressOfData)
		{
			//only resolve by name (ordinal not support)
			if (IHData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				return false;

			else
			{
				//get import func address & cleanup
				IMAGE_IMPORT_BY_NAME* IBN = (PIMAGE_IMPORT_BY_NAME)RVA_VA(IHData->u1.AddressOfData, NT_Head, LocalImg);
				IHData->u1.Function = (ULONGLONG)CPL0.Resolve(IBN->Name, ModuleName);
				MemZero(IBN->Name, StrLen(IBN->Name));

				//import failed
				if (!IHData->u1.Function)
					return false;
			}

			//goto next entry
			IHData++;
		}

		//goto next entry
		ImportDesc++;
	} 
	
	//ok!!!
	return true;
}

void SectWrite(uintptr_t RemoteImg, void* LocalImg, PIMAGE_NT_HEADERS NT_Head, bool Clean = false)
{
	//wipe image
	DWORD ImgRealSize = ((NT_Head->OptionalHeader.SizeOfImage + 4095) & 0xFFFFF000);
	void* ZeroBuff = malloc1(ImgRealSize);
	CPL0.MemCpy((PVOID)RemoteImg, ZeroBuff, (SIZE_T)ImgRealSize);
	free1(ZeroBuff);

	//process sections
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Head);
	for (WORD Cnt = 0; Cnt < NT_Head->FileHeader.NumberOfSections; Cnt++, Sect++)
	{
		auto sectVa = RemoteImg + Sect->VirtualAddress;
		DWORD SectSizeAligned = SizeAlign(max(Sect->Misc.VirtualSize, Sect->SizeOfRawData));

		//protect pte //FORCE EXECUTE
		if (sectVa && SectSizeAligned) {
			for (ULONG i = 0; i < SectSizeAligned; i += 0x1000) {
				auto Pte = CPL0.GetPte(sectVa + i);
				pte PteVal = pte{ CPL0.ReadVA_T<ULONG64>(Pte) };
				PteVal.nx = (bool(Sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) == false);
				CPL0.WriteVA_T<ULONG64>(Pte, PteVal.value);
			}

			//write section
			if (Sect->SizeOfRawData)
				CPL0.MemCpy((PVOID)sectVa, (PCHAR)LocalImg + Sect->PointerToRawData, (SIZE_T)Sect->SizeOfRawData);
		}
	}
}

void FinalizeImage(uintptr_t RemoteImg, PIMAGE_NT_HEADERS NT_Head)
{
	//no access header
	auto Pte = CPL0.GetPte(RemoteImg);
	pte PteVal = pte{ CPL0.ReadVA_T<ULONG64>(Pte) };
	PteVal.present = false; PteVal.nx = true;
	CPL0.WriteVA_T<ULONG64>(Pte, PteVal.value);

	//process sections
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Head);
	for (WORD Cnt = 0; Cnt < NT_Head->FileHeader.NumberOfSections; Cnt++, Sect++)
	{
		auto sectVa = RemoteImg + Sect->VirtualAddress;
		DWORD SectSizeAligned = SizeAlign(max(Sect->Misc.VirtualSize, Sect->SizeOfRawData));

		if (sectVa && SectSizeAligned)
		{
			//DISCARDABLE (ERASE & NOACCESS)
			if (Sect->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			{
				//write zero to section
				void* RndBytes = malloc1(SectSizeAligned);
				CPL0.MemCpy((PVOID)sectVa, RndBytes, (SIZE_T)SectSizeAligned);
				free1(RndBytes);

				//protect pte
				for (ULONG i = 0; i < SectSizeAligned; i += 0x1000) {
					auto Pte = CPL0.GetPte(sectVa + i);
					pte PteVal = pte{ CPL0.ReadVA_T<ULONG64>(Pte) };
					PteVal.present = false; PteVal.nx = true;
					CPL0.WriteVA_T<ULONG64>(Pte, PteVal.value);
				}
			}

			else
			{
				//NORMAL Protect pte
				for (size_t i = 0; i < SectSizeAligned; i += 0x1000) {
					auto Pte = CPL0.GetPte(sectVa + i);
					pte PteVal = pte{ CPL0.ReadVA_T<ULONG64>(Pte) };
					PteVal.rw = bool(Sect->Characteristics & IMAGE_SCN_MEM_WRITE);
					CPL0.WriteVA_T<ULONG64>(Pte, PteVal.value);
				}
			}
		}
	}
}

PVOID AllocateKernelPages(ULONG AllocSize)
{
	auto MiGetPage = CPL0.Resolve(E("MiGetPage"));
	auto MiReservePtes = CPL0.Resolve(E("MiReservePtes"));
	auto MiSystemPartition = CPL0.Resolve(E("MiSystemPartition"));
	auto MiRemovePhysicalMemory = CPL0.Resolve(E("MiRemovePhysicalMemory"));
	auto PteBase = CPL0.ReadVA_T<ULONG64>(CPL0.FindPattern(E("48 23 C8 48 B8 ? ? ? ? ? ? ? ? 48 03 C1 C3")) + 5);
	auto g_MiSystemPteInfo = CPL0.RVA((ULONG64)CPL0.FindPattern(E("48 8D 0D ? ? ? ? 49 8B D6 E8 ? ? ? ? 33 D2")), 7);

	auto PageCount = SizeAlign(AllocSize) / 0x1000;

	//alloc pte's
	pte* pte2 = CPL0.CallInKernel<pte*>(MiReservePtes, g_MiSystemPteInfo, PageCount);
	if (!pte2) return nullptr;

	#define MiGetVirtualAddressMappedByPte(PTE) (PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - PteBase) << 25L) >> 16)

	//get mapped va
	auto mappedVa = MiGetVirtualAddressMappedByPte(pte2);

	//process pages
	for (size_t i = 0; i < PageCount; i++)
	{
		//alloc pfn (phys page)
		newTry:
		auto pfn = CPL0.CallInKernel<ULONG64>(MiGetPage, MiSystemPartition, 0ull, 8ull);
		if (pfn == -1) goto newTry;

		//remove phys page in ranges
		ULONG64 pfnSize = 0x1000; pfnSize = pfnSize >> 12;
		CPL0.CallInKernel(MiRemovePhysicalMemory, pfn, pfnSize);

		//MiMakeValidPte
		pte pte3 = pte{ CPL0.ReadVA_T<ULONG64>(pte2) };
		pte3.present = 1;
		pte3.user_supervisor = 0;
		pte3.rw = 1;
		pte3.pfn = pfn;
		CPL0.WriteVA_T(pte2, pte3.value);

		//goto next pte
		++pte2;
	}

	//mapped system space va
	return mappedVa;
}
