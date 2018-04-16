//
// Created by guoguo on 18-4-3.
//
#include <cstdio>
#include <cstring>
#include "HMELF.h"
#include "HMLog.h"

const char *getSectionTypeToString(uint32_t type) {
    if (type < 0) return NULL;
    const char *retStr;
    switch (type) {
        case SHT_NULL:          retStr = "NULL Header"; break;
        case SHT_PROGBITS:      retStr = "SHT_PROGBITS"; break;
        case SHT_SYMTAB:		retStr = "SHT_SYMTAB";break;
        case SHT_STRTAB:		retStr = "SHT_STRTAB";break;
        case SHT_RELA:		    retStr = "SHT_RELA";break;
        case SHT_HASH:			retStr = "SHT_HASH";break;
        case SHT_DYNAMIC:		retStr = "SHT_DYNAMIC";break;
        case SHT_NOTE:			retStr = "SHT_NOTE";break;
        case SHT_NOBITS:		retStr = "SHT_NOBITS";break;
        case SHT_REL:			retStr = "SHT_REL";break;
        case SHT_SHLIB:			retStr = "SHT_SHLIB";break;
        case SHT_DYNSYM:		retStr = "SHT_DYNSYM";break;
        case SHT_INIT_ARRAY:	retStr = "SHT_INIT_ARRAY";break;
        case SHT_FINI_ARRAY:	retStr = "SHT_FINI_ARRAY";break;
        case SHT_PREINIT_ARRAY:	retStr = "SHT_PREINIT_ARRAY";break;
        case SHT_GROUP:			retStr = "SHT_GROUP";break;
        case SHT_SYMTAB_SHNDX:	retStr = "SHT_SYMTAB_SHNDX";break;
        case SHT_LOOS:			retStr = "SHT_LOOS";break;
        case SHT_LOSUNW:		retStr = "SHT_LOSUNW";break;
        case SHT_SUNW_capinfo:	retStr = "SHT_SUNW_capinfo";break;
        case SHT_SUNW_symsort:	retStr = "SHT_SUNW_symsort";break;
        case SHT_SUNW_tlssort:	retStr = "SHT_SUNW_tlssort";break;
        case SHT_SUNW_LDYNSYM:	retStr = "SHT_SUNW_LDYNSYM";break;
        case SHT_SUNW_dof:		retStr = "SHT_SUNW_dof";break;
        case SHT_SUNW_cap:		retStr = "SHT_SUNW_cap";break;
        case SHT_SUNW_SIGNATURE:retStr = "SHT_SUNW_SIGNATURE";break;
        case SHT_SUNW_ANNOTATE:	retStr = "SHT_SUNW_ANNOTATE";break;
        case SHT_SUNW_DEBUGSTR:	retStr = "SHT_SUNW_DEBUGSTR";break;
        case SHT_SUNW_DEBUG:	retStr = "SHT_SUNW_DEBUG";break;
        case SHT_SUNW_move:		retStr = "SHT_SUNW_move";break;
        case SHT_SUNW_COMDAT:	retStr = "SHT_SUNW_COMDAT";break;
        case SHT_SUNW_syminfo:	retStr = "SHT_SUNW_syminfo";break;
        case SHT_SUNW_verdef:	retStr = "SHT_SUNW_verdef";break;
        case SHT_SUNW_verneed:	retStr = "SHT_SUNW_verneed";break;
        case SHT_HIOS:			retStr = "SHT_HIOS";break;
        case SHT_SPARC_GOTDATA:	retStr = "SHT_SPARC_GOTDATA";break;
        case SHT_AMD64_UNWIND:	retStr = "SHT_AMD64_UNWIND";break;
        case SHT_HIPROC:		retStr = "SHT_HIPROC";break;
        case SHT_LOUSER:		retStr = "SHT_LOUSER";break;
        case SHT_HIUSER:		retStr = "SHT_HIUSER";break;
    }
    return retStr;
}

const char* getAttributeFlagToString(uint64_t flag){
    char retStr[256];
    logd("flag & SHF_WRITE: %u", (flag & SHF_WRITE));
    strcpy (retStr,"Flag ");
    if( (flag & SHF_WRITE) != 0 ){ strcat(retStr, "SHF_WRITE, "); }
    if( (flag & SHF_ALLOC) != 0 ){ strcat(retStr, "SHF_ALLOC, "); }
    if( (flag & SHF_EXECINSTR) != 0 ){ strcat(retStr, "SHF_EXECINSTR, "); }
    if( (flag & SHF_MERGE) != 0 ){ strcat(retStr, "SHF_MERGE, "); }
    if( (flag & SHF_STRINGS) != 0 ){ strcat(retStr, "SHF_STRINGS, "); }
    if( (flag & SHF_INFO_LINK) != 0 ){ strcat(retStr, "SHF_ALLOC, "); }
    if( (flag & SHF_LINK_ORDER) != 0 ){ strcat(retStr, "SHF_INFO_LINK, "); }
    if( (flag & SHF_OS_NONCONFORMING) != 0 ){ strcat(retStr, "SHF_OS_NONCONFORMING, "); }
    if( (flag & SHF_GROUP) != 0 ){ strcat(retStr, "SHF_GROUP, "); }
    if( (flag & SHF_TLS) != 0 ){ strcat(retStr, "SHF_TLS, "); }
    if( (flag & SHF_MASKOS) != 0 ){ strcat(retStr, "SHF_MASKOS, "); }
    if( (flag & SHF_AMD64_LARGE) != 0 ){ strcat(retStr, "SHF_AMD64_LARGE, "); }
    if( (flag & SHF_ORDERED) != 0 ){ strcat(retStr, "SHF_ORDERED, "); }
    if( (flag & SHF_EXCLUDE) != 0 ){ strcat(retStr, "SHF_EXCLUDE, "); }
    if( (flag & SHF_MASKPROC) != 0 ){ strcat(retStr, "SHF_MASKPROC, "); }
    return retStr;
}

const char* getSymbolTypeToString(uint16_t type){
    if (type < 0) return NULL;
    const char *retStr;
    switch (type) {
        case STT_NOTYPE:    retStr = "STT_NOTYPE"; break;
        case STT_OBJECT:    retStr = "STT_OBJECT"; break;
        case STT_FUNC:      retStr = "STT_FUNC"; break;
        case STT_SECTION:   retStr = "STT_SECTION"; break;
        case STT_FILE:      retStr = "STT_FILE"; break;
        case STT_COMMON:    retStr = "STT_COMMON"; break;
        case STT_TLS:       retStr = "STT_TLS"; break;
        case STT_LOOS:      retStr = "STT_LOOS"; break;
        case STT_HIOS:      retStr = "STT_HIOS"; break;
        case STT_LOPROC:    retStr = "STT_LOPROC"; break;
        case STT_HIPROC:    retStr = "STT_HIPROC"; break;
    }
    return retStr;
}

const char* getSymbolBindToString(uint16_t type){
    if (type < 0) return NULL;
    const char *retStr;
    switch (type) {
        case STB_LOCAL:  retStr="STB_LOCAL";break;
        case STB_GLOBAL: retStr="STB_GLOBAL";break;
        case STB_WEAK:   retStr="STB_WEAK";break;
        case STB_LOOS:   retStr="STB_LOOS";break;
        case STB_HIOS:   retStr="STB_HIOS";break;
        case STB_LOPROC: retStr="STB_LOPROC";break;
        case STB_HIPROC: retStr="STB_HIPROC";break;
    }
    return retStr;
}