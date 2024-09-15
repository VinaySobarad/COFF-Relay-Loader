
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <strsafe.h>
#include <shlwapi.h>
#include "COFF_LOADER.h"

#pragma comment(lib, "Shlwapi.lib")

// enable printing debug messages with DEBUG compiler option
#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

// Globals
COFF_MEM_SECTION * 	g_MemSections 		= NULL;
COFF_SYM_ADDR * 	g_MemSymbols 		= NULL;
int 				g_MemSections_size 	= 0;
int 				g_MemSymbols_size 	= 0;
char * 				g_GOT				= NULL;
int 				g_GOT_index			= 0;
void 				(* LaunchGO)(void);


// quick and dirty way to print data of unknown type
int printSecData(char * c, size_t size) {
	char temp[17];												// 16-char line + 1 null byte
	int i = 0;

	while ( i < size) {
		printf("%.8x:  ", i);									// print offset of the bytes
		for (int j = 0 ; j < 16 ; j++) {						// print hex bytes, 16 per line
			if (j == 8) printf(" ");							// put extra space in the middle of the line
			printf("%.2hhx ", *c);								// print the current byte
			if (*c >= 32 && *c <= 126) temp[j] = *c;			// if current byte is printable, save it as-is
			else temp[j] = '.';									// otherwise, save it as a dot
			if ( ++i >= size) {									// if in the last line...
				for ( int a = 0; a < (16 - j) * 2 - 1; a++)		// add extra space between hex values and ascii string
					printf(" ");
				break;
			}
			c++;												// take the next byte
		}
		temp[16] = '\0';										// add the trailing null byte
		printf("%#20s\n\t", temp);								// and print the line as a string
		memset(temp, 0, 16);			
	}
	
	return 0;
}


// resolving symbol addresses in memory
int ResolveSymbols(void) {
	char * symbol= NULL;
	char * DLLname = NULL;
	char * FuncName = NULL;
	int section = 0;
	
	for (int i = 0; i < g_MemSymbols_size ; i++) {
		// get symbol name
		//DEBUG_PRINT("id = %d\n", i);
		symbol = calloc(256, sizeof(char));
		memcpy(symbol, g_MemSymbols[i].Name, strlen(g_MemSymbols[i].Name));
		g_MemSymbols[i].GOTaddress = NULL;
		// skip IMAGE_SYM_ABSOLUTE and IMAGE_SYM_DEBUG symbols (FIXME :)
		if (g_MemSymbols[i].SectionNumber > 0xff) {
			g_MemSymbols[i].InMemoryAddress = NULL;
			continue;
		}

		// skip IMAGE_SYM_UNDEFINED IMAGE_SYM_DEBUG
		if (StrStrIA(symbol, "__UNDEFINED")) {
			g_MemSymbols[i].InMemoryAddress = NULL;
			continue;
		}
		
		// resolve external functions
		if (StrStrIA(symbol, TOKEN_imp)) {
			if ((FuncName = strchr(symbol, '$')) == NULL) {
				DLLname = "kernel32";
				FuncName = symbol + strlen(TOKEN_imp);
			}
			else {
				DLLname = symbol + strlen(TOKEN_imp);
				strtok_s(symbol, "$", &FuncName);
			}
			//DEBUG_PRINT("DLL = %s ; FUNC = %s\n", DLLname, FuncName);
			HANDLE lib = LoadLibraryA(DLLname);
			if (lib != NULL) {
				g_MemSymbols[i].InMemoryAddress = GetProcAddress(lib, FuncName);
				memcpy(g_GOT + (g_GOT_index * 8), &g_MemSymbols[i].InMemoryAddress, sizeof(uint64_t));
				g_MemSymbols[i].GOTaddress = g_GOT + (g_GOT_index * 8);
				g_GOT_index++;
			//DEBUG_PRINT("addr = %llx\n", g_MemSymbols[i].InMemoryAddress);
			}
		}
		else {
			section = g_MemSymbols[i].SectionNumber - 1;
			g_MemSymbols[i].InMemoryAddress = g_MemSections[section].InMemoryAddress + g_MemSymbols[i].Value;
			if (!strncmp(symbol, "go", 3)) {
				LaunchGO = g_MemSymbols[i].InMemoryAddress;
				DEBUG_PRINT("[+] Found entry point = %#llx\n", LaunchGO);
			}			
			//DEBUG_PRINT(" val = %llx\n", g_MemSymbols[i].InMemoryAddress);
		}
		free(symbol);		
	}

	return 0;
}



// main COFF parsing function
int LoadCOFF(unsigned char * COFF_data) {
    COFF_FILE_HEADER * 	coff_header_ptr = NULL;
    COFF_SECTION *		coff_sect_ptr = NULL;
    COFF_RELOCATION * 	coff_reloc_ptr = NULL;
    COFF_SYMBOL * 		coff_sym_ptr = NULL;
	BOOL prn = FALSE;

	// Step 1. Get a pointer to COFF header and print all the fields
	coff_header_ptr = (COFF_FILE_HEADER *) COFF_data;
	DEBUG_PRINT("[+] Machine: %#x\n", coff_header_ptr->Machine);
	DEBUG_PRINT("[+] Number Of Sections: %d\n", coff_header_ptr->NumberOfSections);
	DEBUG_PRINT("[+] Time/Date Stamp: %#x\n", coff_header_ptr->TimeDateStamp);
	DEBUG_PRINT("[+] Pointer To Symbol Table: %#x\n", coff_header_ptr->PointerToSymbolTable);
	DEBUG_PRINT("[+] Number Of Symbols: %d\n", coff_header_ptr->NumberOfSymbols);
	DEBUG_PRINT("[+] Size Of Optional Header: %#x\n", coff_header_ptr->SizeOfOptionalHeader);
	DEBUG_PRINT("[+] Characteristics: %#x\n", coff_header_ptr->Characteristics);
	
	// Step 2. Allocate some extra memory for internal parsing structures (will be used during loading)
	g_MemSections_size = coff_header_ptr->NumberOfSections;
	size_t MemSectionsSize = sizeof(COFF_MEM_SECTION) * g_MemSections_size;
	g_MemSections = calloc(g_MemSections_size, sizeof(COFF_MEM_SECTION));
	if (!g_MemSections) {
		printf("[!] ERROR! Aligned memory allocation failed (g_MemSections : %#x)!\n", GetLastError());
		return -1;
	}
	DEBUG_PRINT("\n[+] Allocated some space for parsed sections (%#llx | %d)\n", g_MemSections, MemSectionsSize);

	// Step 3. Parse and print information about all COFF sections, including data and relocations
	DEBUG_PRINT("\n[+] Starting to parse all sections:");
	for (int i = 0 ; i < g_MemSections_size ; i++) {
		// get pointer to current section to parse
		coff_sect_ptr = (COFF_SECTION *)(COFF_data + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * i));
		
		// if the section is not empty, save the data in the internal structure
		// additionally allocate new memory region for the section and copy data into it

		if (coff_sect_ptr->SizeOfRawData > 0) {
			g_MemSections[i].Counter = i;
			StringCchCopyA(g_MemSections[i].Name, strlen(coff_sect_ptr->Name) + 1, coff_sect_ptr->Name);
			g_MemSections[i].Name[8] = '\0';
			g_MemSections[i].SizeOfRawData = coff_sect_ptr->SizeOfRawData;
			g_MemSections[i].PointerToRawData = coff_sect_ptr->PointerToRawData;
			g_MemSections[i].PointerToRelocations = coff_sect_ptr->PointerToRelocations;
			g_MemSections[i].NumberOfRelocations = coff_sect_ptr->NumberOfRelocations;
			g_MemSections[i].Characteristics = coff_sect_ptr->Characteristics;
			
			// adjust COFF memory region to include new section
			// and copy the data into it
			g_MemSections[i].InMemorySize = g_MemSections[i].SizeOfRawData  + (0x1000 - g_MemSections[i].SizeOfRawData % 0x1000); // align to page size
			g_MemSections[i].InMemoryAddress = VirtualAlloc(NULL,
															g_MemSections[i].InMemorySize,
															MEM_COMMIT | MEM_TOP_DOWN,
															(coff_sect_ptr->Characteristics & IMAGE_SCN_CNT_CODE) 
															? PAGE_EXECUTE_READWRITE
															: PAGE_READWRITE);
			if (g_MemSections[i].InMemoryAddress == NULL) {
				printf("[!] ERROR! Allocating memory for section %d failed! (%#x)\n", i, GetLastError());
				return -1;
			}

			if (coff_sect_ptr->PointerToRawData > 0)
				memcpy(g_MemSections[i].InMemoryAddress, COFF_data + coff_sect_ptr->PointerToRawData, coff_sect_ptr->SizeOfRawData);
			
			prn = TRUE;
		}

#ifdef DEBUG		
		// print the values of the current section
		printf("\n[+] Section #%d:\n", i);
		printf("\tName: %s\n", prn ? g_MemSections[i].Name : coff_sect_ptr->Name);
		printf("\tVirtual Size: %#x\n", coff_sect_ptr->VirtualSize);
		printf("\tVirtual Address: %#x\n", coff_sect_ptr->VirtualAddress);
		printf("\tSize Of Raw Data: %d\n", prn ? g_MemSections[i].SizeOfRawData : coff_sect_ptr->SizeOfRawData);
		printf("\tPointer To Raw Data: %#x\n", prn ? g_MemSections[i].PointerToRawData : coff_sect_ptr->PointerToRawData);
		printf("\tPointer To Relocations: %#x\n", prn ? g_MemSections[i].PointerToRelocations : coff_sect_ptr->PointerToRelocations);
		printf("\tPointer To Line Numbers: %#x\n", coff_sect_ptr->PointerToLineNumbers);
		printf("\tNumber Of Relocations: %d\n", prn ? g_MemSections[i].NumberOfRelocations : coff_sect_ptr->NumberOfRelocations);
		printf("\tNumber Of Line numbers: %d\n", coff_sect_ptr->NumberOfLinenumbers);
		printf("\tCharacteristics: %#x\n", prn ? g_MemSections[i].Characteristics : coff_sect_ptr->Characteristics);
		
		prn = FALSE;

		// also, if section contains any data -> print it out for a quick glance
		if (coff_sect_ptr->SizeOfRawData > 0 && coff_sect_ptr->PointerToRawData > 0) {
			printf("\n\tSection\'s data:\n\t");
			printSecData((char *) COFF_data + coff_sect_ptr->PointerToRawData, (size_t) coff_sect_ptr->SizeOfRawData);
		}

		// now work on all relocations in the section, if there are any		
		if (g_MemSections[i].NumberOfRelocations != 0) {
			printf("\n\tSection's relocations:\n");
			for (int x = 0 ; x < g_MemSections[i].NumberOfRelocations ; x++) {
				coff_reloc_ptr = (COFF_RELOCATION *) (COFF_data + g_MemSections[i].PointerToRelocations + sizeof(COFF_RELOCATION) * x);
				printf("\tReloc: %#4d  | ", x);
				printf("  VAddress:%#9x  |", coff_reloc_ptr->VirtualAddress);
				printf("  SymTab Index:%#5d  |", coff_reloc_ptr->SymbolTableIndex);
				printf("  Type:%#5x\n", coff_reloc_ptr->Type);
			}
		}
#endif
	}

	// Step 4. Allocate some extra memory for internal symbol table (will be used during loading)
	g_MemSymbols_size = coff_header_ptr->NumberOfSymbols;
	g_MemSymbols = calloc(g_MemSymbols_size, sizeof(COFF_SYM_ADDR));
	if (!g_MemSymbols) {
		printf("[!] ERROR! Aligned memory allocation failed (g_MemSymbols : %#x)!\n", GetLastError());
		return -1;
	}
	DEBUG_PRINT("\n[+] Allocated some space for parsed symbols (%#llx | %d)\n", g_MemSymbols, g_MemSymbols_size);
	
	// Step 5. Parse, save and print the entire Symbol Table
	coff_sym_ptr = (COFF_SYMBOL *) (COFF_data + coff_header_ptr->PointerToSymbolTable);
	char * 	coff_strings_ptr = (char *)((COFF_data + coff_header_ptr->PointerToSymbolTable) + g_MemSymbols_size * sizeof(COFF_SYMBOL));
	DEBUG_PRINT("\n\n[+] COFF SYMBOL TABLE\n\n");
	DEBUG_PRINT("------+--------------+-----------+--------+---------------+-------------------\n");
	DEBUG_PRINT("%#4s  |%#9s     |%#9s  |%#6s  |%#14s |%#7s", "No.", "VALUE","SECTION", "TYPE", "STORAGE CLASS", "NAME\n");
	DEBUG_PRINT("------+--------------+-----------+--------+---------------+-------------------\n");
	for (int i = 0 ; i < g_MemSymbols_size ; i++) {
		DEBUG_PRINT("%#4d  |", i);
		DEBUG_PRINT("%#12x  |", coff_sym_ptr[i].Value);
		DEBUG_PRINT("%#9x  |", coff_sym_ptr[i].SectionNumber);
		DEBUG_PRINT("%#6.4d  |", coff_sym_ptr[i].Type);
		DEBUG_PRINT("%#13d  |", coff_sym_ptr[i].StorageClass);
		if (coff_sym_ptr[i].SectionNumber == 0 && coff_sym_ptr[i].StorageClass == 0) {	// according to COFF docs this is IMAGE_SYM_UNDEFINED
			DEBUG_PRINT(" <undefined>");
			StringCchCopyA(g_MemSymbols[i].Name, MEM_SYMNAME_MAX, "__UNDEFINED");
		}
		else
		if (coff_sym_ptr[i].first.Zeros != 0) {			// check if the string is in the Strings Table
			char n[10];									// if not, make sure that a string from ShortName is ending with null byte
			StringCchCopyA(n, strlen(coff_sym_ptr[i].first.ShortName) + 1, coff_sym_ptr[i].first.ShortName);
			n[8] = '\0';
			DEBUG_PRINT(" %s", n);
			StringCchCopyA(g_MemSymbols[i].Name, MEM_SYMNAME_MAX, n);
		}
		else {
			DEBUG_PRINT(" %s", (char *)(coff_strings_ptr + coff_sym_ptr[i].first.Offset));
			StringCchCopyA(g_MemSymbols[i].Name, MEM_SYMNAME_MAX, (char *)(coff_strings_ptr + coff_sym_ptr[i].first.Offset));
		}
		DEBUG_PRINT("\n");

		// save the data inside internal symbols table
		g_MemSymbols[i].Counter = i;
		g_MemSymbols[i].SectionNumber = coff_sym_ptr[i].SectionNumber;
		g_MemSymbols[i].Value = coff_sym_ptr[i].Value;
		g_MemSymbols[i].StorageClass = coff_sym_ptr[i].StorageClass;
		g_MemSymbols[i].InMemoryAddress = NULL;
		
	}
	DEBUG_PRINT("------+--------------+-----------+--------+---------------+-------------------\n\n");
	
	printf("[+] FINISHED PARSING! Now resolving symbols and fixing relocations...\n");

	// Step 6. Resolve symbols addresses in memory
	g_GOT = VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	int ret = ResolveSymbols();
	if (ret != 0)
		return -1;

	DEBUG_PRINT("\n\n[+] RESOLVED COFF SYMBOL TABLE\n\n");
	DEBUG_PRINT("------+--------------+-----------+-----------------+-------------------+-------------------+-------------------\n");
	DEBUG_PRINT("%#4s  |%#9s     |%#9s  |%#15s  |%#16s   |%#15s    |%#7s", "No.", "VALUE", "SECTION", "STORAGE CLASS", "InMEM ADDRESS", "GOT ADDRESS", "NAME\n");
	DEBUG_PRINT("------+--------------+-----------+-----------------+-------------------+-------------------+-------------------\n");
	for (int i = 0 ; i < g_MemSymbols_size ; i++) {
		DEBUG_PRINT("%#4d  |", i);
		DEBUG_PRINT("%#12x  |", g_MemSymbols[i].Value);
		DEBUG_PRINT("%#9x  |", g_MemSymbols[i].SectionNumber);
		DEBUG_PRINT("%#15d  |", g_MemSymbols[i].StorageClass);
		DEBUG_PRINT("%#17llx  |", g_MemSymbols[i].InMemoryAddress);
		DEBUG_PRINT("%#17llx  |", g_MemSymbols[i].GOTaddress);
		DEBUG_PRINT(" %s\n", g_MemSymbols[i].Name);
	}
	DEBUG_PRINT("------+--------------+-----------+-----------------+-------------------+-------------------+-------------------\n");
	
	// Step 7. Fix relocations
	uint64_t what64 = 0;		// 64-bit "what" to write ("what" means - what data to save in the relocated memory)
	int32_t what32 = 0;			// 32-bit "what" to write
	char * where = NULL;		// "where" to write (which memory needs updating)
	int64_t offset64 = 0;		// storage for offsets at relocation position, 64- and 32-bit
	int32_t offset32 = 0;

	for (int i = 0 ; i < g_MemSections_size ; i++ ) {
		if (g_MemSections[i].NumberOfRelocations == 0)
			continue;
		else
			for (int j = 0 ; j < g_MemSections[i].NumberOfRelocations ; j++ ) {
				coff_reloc_ptr = (COFF_RELOCATION *) (COFF_data + g_MemSections[i].PointerToRelocations + sizeof(COFF_RELOCATION) * j);
				//DEBUG_PRINT("sec #%d ; reloc #%d\n", i, j);
				where = NULL;
				switch (coff_reloc_ptr->Type) {
					case IMAGE_REL_AMD64_ADDR64: {		// Type 0x1
						where = g_MemSections[i].InMemoryAddress + coff_reloc_ptr->VirtualAddress;
						memcpy(&offset64, where, sizeof(int32_t));
						what64 = g_MemSymbols[coff_reloc_ptr->SymbolTableIndex].InMemoryAddress + offset64;
						memcpy(where, &what64, sizeof(uint64_t));
						break;
					}
					case IMAGE_REL_AMD64_ADDR32NB: { 	// Type 0x3
						where = g_MemSections[i].InMemoryAddress + coff_reloc_ptr->VirtualAddress;
						memcpy(&offset32, where, sizeof(int32_t));
						what32 = offset32 + (g_MemSymbols[coff_reloc_ptr->SymbolTableIndex].InMemoryAddress) - ((int32_t) where + 4);
						memcpy(where, &what32, sizeof(uint32_t));
						break;
					}
					case IMAGE_REL_AMD64_REL32: { 		// Type 0x4
						where = g_MemSections[i].InMemoryAddress + coff_reloc_ptr->VirtualAddress;
						memcpy(&offset32, where, sizeof(int32_t));
						if (g_MemSymbols[coff_reloc_ptr->SymbolTableIndex].GOTaddress != NULL)
							what32 = (int32_t)((g_MemSymbols[coff_reloc_ptr->SymbolTableIndex].GOTaddress) - ((int32_t) where + 4));
						else
							what32 = offset32 + (g_MemSymbols[coff_reloc_ptr->SymbolTableIndex].InMemoryAddress) - ((int32_t) where + 4);
						memcpy(where, &what32, sizeof(uint32_t));
						break;
					}
					case IMAGE_REL_AMD64_REL32_4: { 	// Type 0x8
						where = g_MemSections[i].InMemoryAddress + coff_reloc_ptr->VirtualAddress;
						memcpy(&offset32, where, sizeof(int32_t));
						what32 = offset32 + (g_MemSymbols[coff_reloc_ptr->SymbolTableIndex].InMemoryAddress) - ((int32_t) where + 4 + 4);
						//DEBUG_PRINT("WHERE = %p\n", where);
						//DEBUG_PRINT("DATA = %x\n", what32);
						memcpy(where, &what32, sizeof(uint32_t));
						break;
					}
					default: {
						printf("[!] ERROR! Reloc type %#x is not supported (SECT = %d : REL = %d)\n", coff_reloc_ptr->Type, i, j);
						return -1;
					}
				}
			}
	}
	
	printf("[+] Everything's set up! Launching the beastie...\n\n");
#ifdef DEBUG	
	DEBUG_PRINT("<hitme>"); getchar();
#endif

	if (LaunchGO != NULL)
		LaunchGO();
	else {
		DEBUG_PRINT("[!] No entry point?\n");
		return -1;
	}

	// cleanup
	// printf("\n[+] We're done! Time to clean up!\n");
	printf("\n[+] Done with the program! cleaning up everyting now!\n");
	// free up all memory regions taken by sections and its metadata
	for (int i = 0 ; i < g_MemSections_size ; i++)
		VirtualFree(g_MemSections[i].InMemoryAddress, 0, MEM_RELEASE);
	VirtualFree(g_MemSections, 0, MEM_RELEASE);

	// free up symbols' metadata and GOT
	VirtualFree(g_MemSymbols, 0, MEM_RELEASE);
	VirtualFree(g_GOT, 0, MEM_RELEASE);
	
	return 0;
}


int main(int argc, char * argv[]) {
	
	if (argc < 2) {
		printf("[!] ERROR! Run: %s <path_2_file>\n", argv[0]);
		return -1;
	}

	printf("[#] %s version %s (C) SEKTOR7 2022\n\n", COFFNAME, COFFVER);

	DEBUG_PRINT("======================\n");
	DEBUG_PRINT("[!] DEBUG MODE IS ON\n");
	DEBUG_PRINT("======================\n\n");
	
	printf("[+] Loading COFF module...");

	// map the COFF file into memory for parsing
	HANDLE COFFfile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (COFFfile == INVALID_HANDLE_VALUE) {
			printf("[!] ERROR! Could not open file: %s (%#x)\n", argv[1], GetLastError());
			return -1;
	}

	HANDLE FileMapping = CreateFileMapping(COFFfile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (FileMapping == NULL) {
			printf("[!] ERROR! Could not call CreateFileMapping (%#x)\n", GetLastError());
			return -1;
	}

	LPVOID COFF_data = MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);
	if (COFF_data == NULL) {
			printf("[!] ERROR! Could not call MapViewOfFile (%#x)\n", GetLastError());
			return -1;
	}

	printf("done.\n"); printf("[+] Time to parse the guy...\n");
	// if file is mapped, proceed with parsing...
	int result = LoadCOFF((unsigned char *) COFF_data);
	if (result)
		printf("[!] Something went wrong. EXITING THE PROGRAM!\n");

	// clean up before saying Good-bye!
	UnmapViewOfFile(COFF_data);
	CloseHandle(FileMapping);
	CloseHandle(COFFfile);
	// printf("[#] Ciao!\nEOF\n");

	printf("[#] END OF THE FUNCTION/PROGRAM\n");
	return 0;
}
