#include "Globals.h"
#include "Inject.h"

//DrvMap Settings
#define ImageBytesName nullptr //nullptr - use cmd-line, BytesName - use byte array

int main()
{
	//prep mmapper
	PrepConsoleApp();

	//set bytes, decrt buffer //32 78 45
	PIMAGE_NT_HEADERS ImageNt; PVOID Image = ImageBytesName;
	if (Image) DecrtBytes(ImageBytesName, sizeof(ImageBytesName), ImageBytesName);

	//parse file - bytes
	switch (ParseFile(ImageNt, &Image)) {
	case BAD_FILE: PrintErr(E("ERR: Bad File"));
	case BAD_CMD_LINE: PrintErr(E("ERR: Wrong CmdLine"));
	case BAD_FILE_SIZE: PrintErr(E("ERR: File Too Large"));
	case BAD_ACCESS_FILE: PrintErr(E("ERR: File Access Error"));
	}

	//alloc local vars
	char OutStr[64];
	wchar_t DrvName[20];
	GenRndStr(DrvName);

	//load driver
	if (!SvcMgr(DrvName, true)) {
		PrintErr(E("[pa1nz0r]ERR: Load Driver"));
	}

	//init kernel mgr
	CPL0.Init();

	//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH//clear TRASH
	//CleanTrace();

	//unload driver
	SvcMgr(DrvName, false);

	//allocate kernel image memory
	DWORD64 ImageBase = (DWORD64)AllocateKernelPages(ImageNt->OptionalHeader.SizeOfImage);
	
	//relocate image
	RelocateImage(ImageNt, ImageBase, Image);

	//fix import
	if (!ResolveImport(Image, ImageNt)) {
		SvcMgr(DrvName, false);
		PrintErr(E("[pa1nz0r]ERR: Import failed"));
	}

	//write image sections
	SectWrite(ImageBase, Image, ImageNt);

	//call driver main
	auto driverEntry = ImageBase + ImageNt->OptionalHeader.AddressOfEntryPoint;
	CPL0.CallInKernel(driverEntry, ImageBase, CPL0.GetDriverBase(E("ntoskrnl.exe")), 0ull);
	
	//cleanup image + protect sections
	FinalizeImage(ImageBase, ImageNt);

	//delete kernel mgr
	CPL0.Release();

	//ok!!!
	PrintErr(E("[pa1nz0r]Img load OK!!!"), FOREGROUND_GREEN);
}