//
// Created by guoguo on 18-4-3.
//

#ifndef ELFHOOK_HMELF_H
#define ELFHOOK_HMELF_H
/*Section Type*/
#include <cstdint>

#define SHT_NULL            0
#define SHT_PROGBITS        1
#define SHT_SYMTAB          2
#define SHT_STRTAB          3
#define SHT_RELA            4
#define SHT_HASH            5
#define SHT_DYNAMIC         6
#define SHT_NOTE            7
#define SHT_NOBITS          8
#define SHT_REL             9
#define SHT_SHLIB           10
#define SHT_DYNSYM          11
#define SHT_INIT_ARRAY      14
#define SHT_FINI_ARRAY      15
#define SHT_PREINIT_ARRAY   16
#define SHT_GROUP           17
#define SHT_SYMTAB_SHNDX    18
#define SHT_LOOS            0x60000000
#define SHT_LOSUNW          0x6fffffef
#define SHT_SUNW_capchain   0x6fffffef
#define SHT_SUNW_capinfo    0x6ffffff0
#define SHT_SUNW_symsort    0x6ffffff1
#define SHT_SUNW_tlssort    0x6ffffff2
#define SHT_SUNW_LDYNSYM    0x6ffffff3
#define SHT_SUNW_dof        0x6ffffff4
#define SHT_SUNW_cap        0x6ffffff5
#define SHT_SUNW_SIGNATURE  0x6ffffff6
#define SHT_SUNW_ANNOTATE   0x6ffffff7
#define SHT_SUNW_DEBUGSTR   0x6ffffff8
#define SHT_SUNW_DEBUG      0x6ffffff9
#define SHT_SUNW_move       0x6ffffffa
#define SHT_SUNW_COMDAT     0x6ffffffb
#define SHT_SUNW_syminfo    0x6ffffffc
#define SHT_SUNW_verdef     0x6ffffffd
#define SHT_SUNW_verneed    0x6ffffffe
#define SHT_SUNW_versym     0x6fffffff
#define SHT_HISUNW          0x6fffffff
#define SHT_HIOS            0x6fffffff
#define SHT_LOPROC          0x70000000
#define SHT_SPARC_GOTDATA   0x70000000
#define SHT_AMD64_UNWIND    0x70000001
#define SHT_HIPROC          0x7fffffff
#define SHT_LOUSER          0x80000000
#define SHT_HIUSER          0xffffffff

/*Section Attribute Flags*/
#define SHF_WRITE               0x1
#define SHF_ALLOC               0x2
#define SHF_EXECINSTR           0x4
#define SHF_MERGE               0x10
#define SHF_STRINGS             0x20
#define SHF_INFO_LINK           0x40
#define SHF_LINK_ORDER          0x80
#define SHF_OS_NONCONFORMING    0x100
#define SHF_GROUP               0x200
#define SHF_TLS                 0x400
#define SHF_MASKOS              0x0ff00000
#define SHF_AMD64_LARGE         0x10000000
#define SHF_ORDERED             0x40000000
#define SHF_EXCLUDE             0x80000000
#define SHF_MASKPROC            0xf0000000


/*Symbol Type*/
#define STT_NOTYPE          0
#define STT_OBJECT          1
#define STT_FUNC            2
#define STT_SECTION         3
#define STT_FILE            4
#define STT_COMMON          5
#define STT_TLS             6
#define STT_LOOS            10
#define STT_HIOS            12
#define STT_LOPROC          13
#define STT_SPARC_REGISTER  13
#define STT_HIPROC          15

/*Symbol bind*/
#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2
#define STB_LOOS    10
#define STB_HIOS    12
#define STB_LOPROC  13
#define STB_HIPROC  15







const char* getSectionTypeToString(uint32_t type);
const char* getAttributeFlagToString(uint64_t flag);

const char* getSymbolTypeToString(uint16_t type);

const char* getSymbolBindToString(uint16_t type);
#endif //ELFHOOK_HMELF_H
