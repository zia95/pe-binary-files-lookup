#ifndef PELOOKUP
#define PELOOKUP

#include<stdio.h>
#include<windows.h>
#include<time.h>
#include<stdbool.h>

HANDLE g_hFile;		//handle of pe file
HANDLE g_hMap;		//handle of map object
LPVOID g_lpFile;	//base of pe file

//PIMAGE_DOS_HEADER g_pImgDosHdr;
//PIMAGE_NT_HEADERS32 g_pImgNtHdr;

void print_hex_dump(char* begin, char* end)
{

	int size = end - begin;
	unsigned int secAddress = (unsigned int)begin;


	int i = 1, temp = 0;
	wchar_t buf[18];          //Buffer      to store the character dump displayed at the right side
	printf("\n\n%x: |", secAddress);

	buf[temp] = ' ';  //initial space
	buf[temp + 16] = ' ';  //final space    
	buf[temp + 17] = 0;  //End of buf
	temp++;                           //temp = 1;
	for (; i <= size; i++, begin++, temp++)
	{
		buf[temp] = !iswcntrl((*begin) & 0xff) ? (*begin) & 0xff : '.';
		printf("%-3.2x", (*begin) & 0xff);

		if (i % 16 == 0) {    //print the chracter dump to the right       
			_putws(buf);
			if (i + 1 <= size)printf("%x: ", secAddress += 16);
			temp = 0;
		}
		if (i % 4 == 0)printf("|");
	}
	if (i % 16 != 0) {
		buf[temp] = 0;
		for (; i % 16 != 0; i++)
			printf("%-3.2c", ' ');
		_putws(buf);
	}
}

LPVOID pe_file_open(const char* file)
{
	g_hFile = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_hFile == INVALID_HANDLE_VALUE)
		return NULL;

	g_hMap = CreateFileMappingA(g_hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (!g_hMap)
	{
		CloseHandle(g_hFile);
		return NULL;
	}

	g_lpFile = MapViewOfFile(g_hMap, FILE_MAP_READ, 0, 0, 0);

	if (g_lpFile)
		return g_lpFile;

	CloseHandle(g_hMap);
	CloseHandle(g_hFile);
	return NULL;
}

void pe_file_close()
{
	UnmapViewOfFile(g_lpFile);
	CloseHandle(g_hMap);
	CloseHandle(g_hFile);
}

const char* get_machine(WORD code)
{
	switch (code)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN: return "<UNKNOWN>";
	case IMAGE_FILE_MACHINE_TARGET_HOST: return "TARGET_HOST";
	case IMAGE_FILE_MACHINE_I386: return "Intel 386";
	case IMAGE_FILE_MACHINE_R3000: return "MIPS little-endian, 0x160 big-endian";
	case IMAGE_FILE_MACHINE_R4000: return "MIPS little-endian";
	case IMAGE_FILE_MACHINE_R10000: return "MIPS little-endian";
	case IMAGE_FILE_MACHINE_WCEMIPSV2: return "MIPS little-endian WCE v2";
	case IMAGE_FILE_MACHINE_ALPHA: return "Alpha_AXP";
	case IMAGE_FILE_MACHINE_SH3: return "SH3 little-endian";
	case IMAGE_FILE_MACHINE_SH3DSP: return "SH3DSP";
	case IMAGE_FILE_MACHINE_SH3E: return "SH3E little-endian";
	case IMAGE_FILE_MACHINE_SH4: return "SH4 little-endian";
	case IMAGE_FILE_MACHINE_SH5: return "SH5";
	case IMAGE_FILE_MACHINE_ARM: return "ARM Little-Endian";
	case IMAGE_FILE_MACHINE_THUMB: return "ARM Thumb/Thumb-2 Little-Endian";
	case IMAGE_FILE_MACHINE_ARMNT: return "ARM Thumb-2 Little-Endian";
	case IMAGE_FILE_MACHINE_AM33: return "AM33";
	case IMAGE_FILE_MACHINE_POWERPC: return "IBM PowerPC Little-Endian";
	case IMAGE_FILE_MACHINE_POWERPCFP: return "POWERPCFP";
	case IMAGE_FILE_MACHINE_IA64: return "Intel 64";
	case IMAGE_FILE_MACHINE_MIPS16: return "MIPS";
	case IMAGE_FILE_MACHINE_ALPHA64: return "ALPHA64, AXP64";
	case IMAGE_FILE_MACHINE_MIPSFPU: return "MIPS";
	case IMAGE_FILE_MACHINE_MIPSFPU16: return "MIPS";
		//case IMAGE_FILE_MACHINE_AXP64: return "AXP64";
	case IMAGE_FILE_MACHINE_TRICORE: return "";
	case IMAGE_FILE_MACHINE_CEF: return "Infineon";
	case IMAGE_FILE_MACHINE_EBC: return "EFI Byte Code";
	case IMAGE_FILE_MACHINE_AMD64: return "AMD64 (K8)";
	case IMAGE_FILE_MACHINE_M32R: return "M32R little-endian";
	case IMAGE_FILE_MACHINE_ARM64: return "ARM64 Little-Endian";
	case IMAGE_FILE_MACHINE_CEE: return "CEE";
	}
	return NULL;
}

const char* get_subsystem(WORD code)
{
	switch (code)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN: return "<UNKNOWN>";
	case IMAGE_SUBSYSTEM_NATIVE: return "No subsystem required (device drivers and native system processes)";
	case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows graphical user interface (GUI) subsystem";
	case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows character-mode user interface (CUI) subsystem";
	case IMAGE_SUBSYSTEM_OS2_CUI: return "OS/2 CUI subsystem";
	case IMAGE_SUBSYSTEM_POSIX_CUI: return "POSIX CUI subsystem";
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "Windows CE system";
	case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "Extensible Firmware Interface (EFI) application";
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI driver with boot services";
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "EFI driver with run-time services";
	case IMAGE_SUBSYSTEM_EFI_ROM: return "EFI ROM image.";
	case IMAGE_SUBSYSTEM_XBOX: return "Xbox system";
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Boot application";
	}
	return NULL;
}

#define PRINT_HEADER(TXT) printf("\n==================================[%s]==================================\n\n", TXT)
#define PRINT_HEADER_ADDR(TXT, ADDR) printf("\n==================================[%s(0x%p)]==================================\n\n", TXT, ADDR)
#define PRINT_SUBHEADER_ADDR(TXT, ADDR) printf("=============[%s(0x%p)]:\n", TXT, ADDR)

#define FLAG_EXIST_PRINT(FLG, CFLG, STR) if((FLG & CFLG) == CFLG) printf("\t->%s(0x%x)\n", STR, CFLG)
#define FLAG_PRINT_IF_NULL(FLG, TXT) if(FLG==0) printf("\t*%s\n", TXT)

PIMAGE_DOS_HEADER print_dos_header(LPVOID file)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)file;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PRINT_HEADER_ADDR("DosHeader", dosHeader);

	printf("Magic number: 0x%x\n", dosHeader->e_magic);
	printf("Bytes on last page of file: 0x%x\n", dosHeader->e_cblp);
	printf("Pages in file: 0x%x\n", dosHeader->e_cp);
	printf("Relocations: 0x%x\n", dosHeader->e_crlc);
	printf("Size of header in paragraphs: 0x%x\n", dosHeader->e_cparhdr);
	printf("Minimum extra paragraphs needed: 0x%x\n", dosHeader->e_minalloc);
	printf("Maximum extra paragraphs needed: 0x%x\n", dosHeader->e_maxalloc);
	printf("Initial (relative) SS value: 0x%x\n", dosHeader->e_ss);
	printf("Initial SP value: 0x%x\n", dosHeader->e_sp);
	printf("Initial SP value: 0x%x\n", dosHeader->e_sp);
	printf("Checksum: 0x%x\n", dosHeader->e_csum);
	printf("Initial IP value: 0x%x\n", dosHeader->e_ip);
	printf("Initial (relative) CS value: 0x%x\n", dosHeader->e_cs);
	printf("File address of relocation table: 0x%x\n", dosHeader->e_lfarlc);
	printf("Overlay number: 0x%x\n", dosHeader->e_ovno);
	printf("OEM identifier (for e_oeminfo): 0x%x\n", dosHeader->e_oemid);
	printf("OEM information; e_oemid specific: 0x%x\n", dosHeader->e_oeminfo);
	printf("File address of new exe header: 0x%x\n", dosHeader->e_lfanew);


	return dosHeader;
}

void print_file_header(PIMAGE_FILE_HEADER pfh)
{
	PRINT_HEADER_ADDR("FileHeader", pfh);

	printf("Machine Architechture: %s(%x)\n", get_machine(pfh->Machine), pfh->Machine);
	printf("Number of sections: %d\n", pfh->NumberOfSections);

	char time[30];
	memset(&time, 0, 30);
	if (ctime_s(time, 29, (const time_t*)& pfh->TimeDateStamp) == 0)
		printf("Time stamp: %s\n", time);


	printf("Pointer to symbol table: 0x%x\n", pfh->PointerToSymbolTable);
	printf("Number of symbol: %d\n", pfh->NumberOfSymbols);
	printf("Size of optional header: %d\n", pfh->SizeOfOptionalHeader);



	printf("Characteristics:\n");

	FLAG_PRINT_IF_NULL(pfh->Characteristics, "No characteristics exist.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_RELOCS_STRIPPED, "Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_EXECUTABLE_IMAGE, "The file is executable(there are no unresolved external references).");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_LINE_NUMS_STRIPPED, "COFF line numbers were stripped from the file.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_LOCAL_SYMS_STRIPPED, "COFF symbol table entries were stripped from file.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_AGGRESIVE_WS_TRIM, "Aggressively trim the working set.This value is obsolete.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_LARGE_ADDRESS_AWARE, "The application can handle addresses larger than 2 GB.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_BYTES_REVERSED_LO, "The bytes of the word are reversed. This flag is obsolete.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_32BIT_MACHINE, "The computer supports 32-bit words.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_DEBUG_STRIPPED, "Debugging information was removed and stored separately in another file.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "If the image is on removable media, copy it to and run it from the swap file.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_NET_RUN_FROM_SWAP, "If the image is on the network, copy it toand run it from the swap file.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_SYSTEM, "The image is a system file.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_DLL, "The image is a DLL file.While it is an executable file, it cannot be run directly.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_UP_SYSTEM_ONLY, "The file should be run only on a uniprocessor computer.");

	FLAG_EXIST_PRINT(pfh->Characteristics, IMAGE_FILE_BYTES_REVERSED_HI, "The bytes of the word are reversed.This flag is obsolete.");

}

void print_opt_header32(PIMAGE_OPTIONAL_HEADER32 poh)
{
	PRINT_HEADER_ADDR("OptionalHeader32", poh);

	switch (poh->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC: printf("Magic: 32bit application(0x%x)\n", poh->Magic);
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC: printf("Magic: 64bit application(0x%x)\n", poh->Magic);
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC: printf("Magic: The file is a ROM image(0x%x)\n", poh->Magic);
	default: printf("Magic: 0x%x\n", poh->Magic);
	}


	printf("Major Linker Version: 0x%x\n", poh->MajorLinkerVersion);
	printf("Minor Linker Version: 0x%x\n", poh->MinorLinkerVersion);
	printf("Size Of Code: 0x%x\n", poh->SizeOfCode);
	printf("Size Of Initialized Data: 0x%x\n", poh->SizeOfInitializedData);
	printf("Size Of UnInitialized Data: 0x%x\n", poh->SizeOfUninitializedData);
	printf("Address Of Entry Point (.text): 0x%x\n", poh->AddressOfEntryPoint);
	printf("Base Of Code: 0x%x\n", poh->BaseOfCode);
	printf("Base Of Data: 0x%x\n", poh->BaseOfData);
	printf("Image Base: 0x%x\n", poh->ImageBase);
	printf("Section Alignment: 0x%x\n", poh->SectionAlignment);
	printf("File Alignment: 0x%x\n", poh->FileAlignment);
	printf("Major Operating System Version: 0x%x\n", poh->MajorOperatingSystemVersion);
	printf("Minor Operating System Version: 0x%x\n", poh->MinorOperatingSystemVersion);
	printf("Major Image Version: 0x%x\n", poh->MajorImageVersion);
	printf("Minor Image Version: 0x%x\n", poh->MinorImageVersion);
	printf("Major Subsystem Version: 0x%x\n", poh->MajorSubsystemVersion);
	printf("Minor Subsystem Version: 0x%x\n", poh->MinorSubsystemVersion);
	printf("Win32 Version Value: 0x%x\n", poh->Win32VersionValue);
	printf("Size Of Image: 0x%x\n", poh->SizeOfImage);
	printf("Size Of Headers: 0x%x\n", poh->SizeOfHeaders);
	printf("CheckSum: 0x%x\n", poh->CheckSum);


	printf("Subsystem: %s(%x)\n", get_subsystem(poh->Subsystem), poh->Subsystem);
	printf("DllCharacteristics:\n");

	FLAG_PRINT_IF_NULL(poh->DllCharacteristics, "No characteristics exist.");
	
	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,"The DLL can be relocated at load time.");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "Code integrity checks are forced.If you set this flagand a section contains only uninitialized data, set the PointerToRawData member of IMAGE_SECTION_HEADER for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified.");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "The image is compatible with data execution prevention(DEP).");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "The image is isolation aware, but should not be isolated.");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_SEH, "The image does not use structured exception handling(SEH).No handlers can be called in this image.");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_BIND, "Do not bind the image.");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "A WDM driver.");

	FLAG_EXIST_PRINT(poh->DllCharacteristics, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "The image is terminal server aware.");

	printf("Size Of Stack Reserve: 0x%x\n", poh->SizeOfStackReserve);
	printf("Size Of Stack Commit: 0x%x\n", poh->SizeOfStackCommit);
	printf("Size Of Heap Reserve: 0x%x\n", poh->SizeOfHeapReserve);
	printf("Size Of Heap Commit: 0x%x\n", poh->SizeOfHeapCommit);
	/////////////////printf("\t0x%x\t\tLoader Flags\n", poh->LoaderFlags); 
	printf("Number Of Rva And Sizes: 0x%x\n", poh->NumberOfRvaAndSizes);
}

PIMAGE_NT_HEADERS32 print_nt_header32(PIMAGE_DOS_HEADER dos, bool file_header, bool opt_header)
{
	PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)((DWORD)(dos)+(dos->e_lfanew));

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PRINT_HEADER_ADDR("NtHeader", nt);

	//printf("\nPrinting nt header...\n");
	printf("Signature: 0x%x\n", nt->Signature);

	if (file_header)
		print_file_header(&nt->FileHeader);

	if (opt_header)
		print_opt_header32(&nt->OptionalHeader);


	return nt;
}


void print_sections32(PIMAGE_NT_HEADERS32 pnh, bool import_dir)
{
	DWORD sectionLocation = (DWORD)pnh + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)pnh->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = pnh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	PIMAGE_SECTION_HEADER importSection = NULL;

	PRINT_HEADER("Sections");
	for (WORD i = 0; i < pnh->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;

		PRINT_SUBHEADER_ADDR("Section", sectionHeader);
#pragma region Print section struct


		printf("Section name: %s\n", sectionHeader->Name);
		printf("Virtual address: 0x%x\n", sectionHeader->VirtualAddress);
		printf("Virtual size: 0x%x\n", sectionHeader->Misc.VirtualSize);
		printf("Size of raw data: 0x%x\n", sectionHeader->SizeOfRawData);
		printf("Pointer to raw data: 0x%x\n", sectionHeader->PointerToRawData);
		printf("Pointer to relocations: 0x%x\n", sectionHeader->PointerToRelocations);
		printf("Pointer to line numbers: 0x%x\n", sectionHeader->PointerToLinenumbers);
		printf("Number of relocations: %d\n", sectionHeader->NumberOfRelocations);
		printf("Number of line numbers: %d\n", sectionHeader->NumberOfLinenumbers);

		printf("Characteristics:\n");

		FLAG_PRINT_IF_NULL(sectionHeader->Characteristics, "No characteristics exist.");

		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_TYPE_NO_PAD, "The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_CNT_CODE, "The section contains executable code.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_CNT_INITIALIZED_DATA, "The section contains initialized data.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_CNT_UNINITIALIZED_DATA, "The section contains uninitialized data.\n");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_LNK_INFO, "The section contains comments or other information. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_LNK_REMOVE, "The section will not become part of the image. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_LNK_COMDAT, "The section contains COMDAT data. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_NO_DEFER_SPEC_EXC, "Reset speculative exceptions handling bits in the TLB entries for this section.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_GPREL, "The section contains data referenced through the global pointer.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_1BYTES, "Align data on a 1-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_2BYTES, "Align data on a 2-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_4BYTES, "Align data on a 4-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_8BYTES, "Align data on a 8-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_16BYTES, "Align data on a 16-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_32BYTES, "Align data on a 32-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_64BYTES, "Align data on a 64-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_128BYTES, "Align data on a 128-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_256BYTES, "Align data on a 256-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_512BYTES, "Align data on a 512-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_1024BYTES, "Align data on a 1024-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_2048BYTES, "Align data on a 2048-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_4096BYTES, "Align data on a 4096-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_ALIGN_8192BYTES, "Align data on a 8192-byte boundary. This is valid only for object files.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_LNK_NRELOC_OVFL,
			"The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_DISCARDABLE, "The section can be discarded as needed.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_NOT_CACHED, "The section cannot be cached.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_NOT_PAGED, "The section cannot be paged.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_SHARED, "The section can be shared in memory.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_EXECUTE, "The section can be executed as code.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_READ, "The section can be read.");
		FLAG_EXIST_PRINT(sectionHeader->Characteristics, IMAGE_SCN_MEM_WRITE, "The section can be written to.");
#pragma endregion
		printf("\n\n");


		// save section that contains import directory table
		DWORD secHdrVAbegin = sectionHeader->VirtualAddress;
		DWORD secHdrVAend = sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize;

		importSection = (importDirectoryRVA >= secHdrVAbegin && importDirectoryRVA < secHdrVAend) ? sectionHeader : importSection;

		sectionLocation += sectionSize;
	}
	if (importSection)
	{
		DWORD rawOffset = 0;
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
		// get file offset to import table
		rawOffset = (DWORD)g_lpFile + importSection->PointerToRawData - importSection->VirtualAddress;


		// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: 
		//imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + importDirectoryRVA);

		PRINT_HEADER("Imports");

		const char* module_name = NULL;//module name where functions are imported from.
		DWORD thunkOff = 0;//thunk data offset unbounded or bounded
		PIMAGE_THUNK_DATA32 thunkData = NULL;// thunk data 
		PIMAGE_IMPORT_BY_NAME imptByName = NULL;//getting imported function
		for (; importDescriptor->Name != 0; importDescriptor++)
		{
			module_name = (const char*)(rawOffset + importDescriptor->Name);
			thunkOff = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
			thunkData = (PIMAGE_THUNK_DATA32)(rawOffset + thunkOff);

			PRINT_SUBHEADER_ADDR("ImportThunkData", thunkData);

			printf("Imports of '%s':\n", module_name);

			for (; thunkData->u1.AddressOfData != 0; thunkData++)
			{
				if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					printf("\t->Ordinal: %x\n", (WORD)thunkData->u1.AddressOfData);
				}
				else
				{

					imptByName = (PIMAGE_IMPORT_BY_NAME)(rawOffset + thunkData->u1.AddressOfData);
					printf("\t->%s\n", imptByName->Name);
				}
			}
		}
	}
}

/* ONLY WORKS WHEN PE IS RUNNING
void print_imports(PIMAGE_DOS_HEADER dos)
{
	//unsigned int* iatEntry;



	PIMAGE_NT_HEADERS ntHdrPtr = (PIMAGE_NT_HEADERS)(dos + (dos)->e_lfanew);
	//PIMAGE_DATA_DIRECTORY importDir = &ntHdrPtr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	DWORD importRVA = ntHdrPtr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importSize = ntHdrPtr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;


	PIMAGE_IMPORT_DESCRIPTOR importDescriptorPtr = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)dos + importRVA);
	DWORD importEndAddress = (DWORD)dos + importRVA + importSize;


	char* importDescriptorName = NULL;
	for (; (DWORD)importDescriptorPtr <= importEndAddress; importDescriptorPtr++)
	{
		importDescriptorName = (char*)((DWORD)dos + importDescriptorPtr->Name);
		if (importDescriptorName)
		{
			printf(importDescriptorName);
			PIMAGE_THUNK_DATA32 thunkData = (PIMAGE_THUNK_DATA32)((DWORD)dos + importDescriptorPtr->FirstThunk);
			PIMAGE_IMPORT_BY_NAME imptByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)dos + thunkData->u1.AddressOfData);
		}
	}
}
*/


#endif // !PELOOKUP