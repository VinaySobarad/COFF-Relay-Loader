#define COFFNAME			"COFF_LOADER"
#define COFFVER				"0.1-alpha"
#define MEM_SYMNAME_MAX		100
#define MAP_SIZE			100 * 1024
#define TOKEN_imp			"__imp_"
#define	TOKEN_kernel32		"KERNEL32"

typedef struct _COFF_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_FILE_HEADER;


#pragma pack(push,1)
/* Size of 40 */
typedef struct _COFF_SECTION {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} COFF_SECTION;


/* size of 10 */
typedef struct _COFF_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} COFF_RELOCATION;


/* size of 18 */
typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
		struct {
			uint32_t Zeros;
			uint32_t Offset;
		};
    } first;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;


typedef struct _COFF_MEM_SECTION {
	uint32_t	Counter;				// section position
	char		Name[10];				// saved name of section with trailing null bytes
	uint32_t	SizeOfRawData;			// size of section
	uint32_t	PointerToRawData;		// offset to section's data
	uint32_t	PointerToRelocations;	// offset to section's relocation info
	uint16_t	NumberOfRelocations;	// total number of relocations in the section
	uint32_t	Characteristics;		// section's characteristics
	uint64_t	InMemoryAddress;		// allocated memory region to store the section
	uint32_t	InMemorySize;			// size of allocated memory	
} COFF_MEM_SECTION;


typedef struct _COFF_SYM_ADDR {
	uint32_t	Counter;				// symbol position in the Symbol Table
	char		Name[MEM_SYMNAME_MAX];	// might be insufficient in extreme cases
	uint16_t	SectionNumber;			// section number containing symbol
	uint32_t	Value;					// offset inside section containing symbol	
	uint8_t		StorageClass;			// symbol storage class
	uint64_t	InMemoryAddress;		// address of the symbol in memory
	uint64_t	GOTaddress;				// address of the symbol in Global Offset Table
} COFF_SYM_ADDR;
#pragma pack(pop)

// src: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only

#define MACHINETYPE_AMD64 0x8664

// Section Flags
#define IMAGE_SCN_CNT_CODE			0x00000020

/* AMD64 Specific types */
#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
/* Most common from the looks of it, just 32-bit relative address from the byte following the relocation */
#define IMAGE_REL_AMD64_REL32       0x0004
/* Second most common, 32-bit address without an image base. Not sure what that means... */
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

/*i386 Relocation types */

#define IMAGE_REL_I386_ABSOLUTE     0x0000
#define IMAGE_REL_I386_DIR16        0x0001
#define IMAGE_REL_I386_REL16        0x0002
#define IMAGE_REL_I386_DIR32        0x0006
#define IMAGE_REL_I386_DIR32NB      0x0007
#define IMAGE_REL_I386_SEG12        0x0009
#define IMAGE_REL_I386_SECTION      0x000A
#define IMAGE_REL_I386_SECREL       0x000B
#define IMAGE_REL_I386_TOKEN        0x000C
#define IMAGE_REL_I386_SECREL7      0x000D
#define IMAGE_REL_I386_REL32        0x0014

/* Section Characteristic Flags */

#define IMAGE_SCN_MEM_WRITE					0x80000000
#define IMAGE_SCN_MEM_READ					0x40000000
#define IMAGE_SCN_MEM_EXECUTE				0x20000000
#define IMAGE_SCN_ALIGN_16BYTES				0x00500000
#define IMAGE_SCN_MEM_NOT_CACHED			0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED				0x08000000
#define IMAGE_SCN_MEM_SHARED				0x10000000
#define IMAGE_SCN_CNT_CODE					0x00000020
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA	0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE			0x02000000
