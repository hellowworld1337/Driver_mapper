
#include <aclapi.h>
#include <DbgHelp.h>
#include <sddl.h>

//#pragma comment(lib, "Imagehlp.lib")
//#pragma comment(lib, "Dbghelp.lib")

template<typename Arg>
PBYTE GetSymAddress(const char* FilePath, Arg SymName)
{
	//init pdb engine
	SymInitialize((HANDLE)-1/*GetCurrentProcess()*/, E("http://msdl.microsoft.com/download/symbols"), false);
	
	//set output mode (cur dir)
	SymSetOptions(SYMOPT_ALLOW_ABSOLUTE_SYMBOLS /*| SYMOPT_DEBUG*/);
	
	//load pdb file
	auto ModBase = SymLoadModule64((HANDLE)-1/*GetCurrentProcess()*/, nullptr, FilePath, nullptr, 0, 0);
	if (!ModBase) {
		SymCleanup((HANDLE)-1/*GetCurrentProcess()*/);
		return nullptr;
	}

	//get pdb path
	IMAGEHLP_MODULEW64 ModuleInfo;
	ModuleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
	SymGetModuleInfoW64((HANDLE)-1/*GetCurrentProcess()*/, ModBase, &ModuleInfo);

	//build symbol name
	char SymNameFix[64];
	StrCpy(ModuleInfo.ModuleName, SymNameFix);
	StrCat(SymNameFix, "!"); 
	StrCat(SymNameFix, SymName);

	//get func
	PSYMBOL_INFO_PACKAGE SIP = (PSYMBOL_INFO_PACKAGE)_alloca(sizeof(SYMBOL_INFO_PACKAGE));
	PBYTE ResolvedFunc = nullptr;
	SIP->si.MaxNameLen = sizeof(SIP->name);
	SIP->si.SizeOfStruct = sizeof(SYMBOL_INFO);
	if (SymFromName((HANDLE)-1/*GetCurrentProcess()*/, SymNameFix, &SIP->si)) {
		ResolvedFunc = (PBYTE)SIP->si.Address - ModBase;
	}

	//cleanup
	SymUnloadModule64((HANDLE)-1/*GetCurrentProcess()*/, ModBase);
	//DeleteFileW(ModuleInfo.LoadedPdbName);
	SymCleanup((HANDLE)-1/*GetCurrentProcess()*/);

	//ret func offset
	return ResolvedFunc;
}
