//
// Created by guoguo on 18-3-31.
//
#include <elf.h>
#include <math.h>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "hook_elf.h"
#include "HMLog.h"
#include "HMELF.h"

#define LOG_TAG "HookElf"

void hexdump(const char* value, int size){
    if(value == NULL)
        return;

    int hexBufferLen = size * 3 + size / 16 + 1;
    char* hexBuffer = (char*)malloc(hexBufferLen);
    if(hexBuffer == NULL) return;
    memset(hexBuffer, 0x00, hexBufferLen);

    int bufferStep = 0;
    sprintf(hexBuffer, "\n");
    bufferStep++;
    for (int i = 0; i < size; i++) {
        if( (i+1) % 16 == 0){
            sprintf(hexBuffer + bufferStep, "%02x\n", (value[i] & 0xFF));
        } else {
            sprintf(hexBuffer + bufferStep, "%02x ", (value[i] & 0xFF));
        }
        bufferStep +=3;
    }
    sprintf(hexBuffer + bufferStep, "\n");
    logd("%s", hexBuffer);
    free(hexBuffer);

}

uint64_t getLibBaseAddr(const char* libName){
    uint64_t libbaseAddr = 0;
    const char* mapPath = "/proc/self/maps";
    FILE* fp = fopen(mapPath, "r");
    if(fp == NULL) return libbaseAddr;

    char line[256] = {0x00};
    while ( fgets(line, 256,fp) != NULL ){
        if(strstr(line, libName) == NULL)continue;
        logd("line: %s", line);
        char* temp = strtok(line, "-");
        libbaseAddr = strtoull(temp, NULL, 16);
        memset(line, 0x00, 256);
        break;
    }

    fclose(fp);

    return libbaseAddr;
}

uint64_t getLibEndAddr(const char* libName){
    uint64_t libEndAddr = 0;
    const char* mapPath = "/proc/self/maps";
    FILE* fp = fopen(mapPath, "r");
    if(fp == NULL) return libEndAddr;

    char line[256] = {0x00};
    char preLine[256]= {0x00};
    while ( fgets(line, 256,fp) != NULL ){
        if(strstr(preLine, libName) != NULL &&
           strstr(line, libName) == NULL){
            logd("preLine: %s", preLine);
            logd("line: %s", line);
            char* temp = strtok(preLine, "-");;
            libEndAddr = strtoull(strtok(NULL, " "), NULL, 16);
            break;
        }
        memcpy(preLine, line, 256);
        memset(line, 0x00, 256);
    }
    logd("libEndAddr: 0x%llx", libEndAddr);
    fclose(fp);

    return libEndAddr;
}

const char* getLibPath(const char* libName){
    if(libName == NULL) return NULL;
    if( *libName == '/')
        return libName;
    char* libPath = NULL;
    const char* mapPath = "/proc/self/maps";
    FILE* fp = fopen(mapPath, "r");

    if(fp == NULL) return NULL;

    char line[256] = {0x00};
    while ( fgets(line, 256,fp) != NULL ){
        if(strstr(line, libName) == NULL)continue;
        libPath = strchr(line, '/');
        break;
    }

    fclose(fp);
    return libPath;
}

SoInfo::SoInfo(const char* name, const struct stat* file_stat,
       off64_t file_offset){
    logd("name: %s", name);
    if(name == NULL)return ;
    int readCount = 0;
    if(access(name, O_RDONLY) == 0){
        int fd = open(name, O_RDONLY);
        if(fd < 0){
            loge("Cannot open the file: %s, error: %s", name, strerror(errno));
            return;
        }
        memcpy(soName, name, strlen(name));

        char elfIndent[EI_NIDENT] = {0x00};
        readCount = read(fd, elfIndent, EI_NIDENT);
        if(readCount != EI_NIDENT){
            loge("Cannot open the file: %s, error: %s", name, strerror(errno));
            return;
        }
        close(fd);

        this->is64Bit = elfIndent[EI_CLASS] == 2 ? true:false;

        if(is64Bit){
            parser64BitSo(name);
        } else {
            parser32BitSo(name);
        }
    } else {
        uint64_t  baseAddr = getLibBaseAddr(name);
        uint64_t  endAddr = getLibEndAddr(name);
        uint64_t fileSize = endAddr - baseAddr;

        memcpy(this->soName, name, strlen(name));
        if(is64Bit){
            parser64BitSo(baseAddr, fileSize);
        } else {
            parser32BitSo(baseAddr, fileSize);
        }
    }
}

void SoInfo::freeData(){

}


void SoInfo::parser32BitSo(const char* libPath){
    logd("parser32BitSo, libPath: %s", libPath);
}
void SoInfo::parser64BitSo(const char* libPath){
    int fd = open(libPath, O_RDONLY);
    if(fd < 0) return;

    mElfHeader = (struct ElfHeader_s*)malloc(sizeof(struct ElfHeader_s));
    if(mElfHeader == NULL){
        loge("Cannot malloc the memory, error: %s", strerror(errno));
        return;
    }
    memset(mElfHeader, 0x00, sizeof(struct ElfHeader_s));
    int readCount = read(fd, mElfHeader, sizeof(struct ElfHeader_s));
    if(readCount != sizeof(struct ElfHeader_s)){
        loge("ReadCount: %d, sectionNameStringSize: %d", readCount, sizeof(struct ElfHeader_s));
        return;
    }
    mSectionCount = mElfHeader->mSectionHeaderNum;

/*cache all section headers START*/
    int sectionHeadersSize = mElfHeader->mSectionHeaderNum * mElfHeader->mSectionHeaderSize;

    mSectionHeaders = (struct SectionHeader_s*)malloc(sectionHeadersSize);
    if(mSectionHeaders == NULL){
        loge("Cannot malloc for mSectionHeaders, err: %s",strerror(errno));
        return;
    }

    lseek(fd, mElfHeader->mSectionHeaderOffset,SEEK_SET);
    readCount = read(fd, mSectionHeaders, sectionHeadersSize);
    if(readCount != sectionHeadersSize){
        loge("read faild! readCount: %d, sectionHeadersSize: %d", readCount, sectionHeadersSize);
        return;
    }
/*cache all section headers END*/

/*Init all section content to data START*/
    mData = (uint8_t**)malloc(mSectionCount * sizeof(void*));
    if(mData == NULL) return;
    struct SectionHeader_s *pTempSectionHeader = NULL;
    for (int j = 0; j < mSectionCount; ++j) {
        pTempSectionHeader = &mSectionHeaders[j];
        uint8_t *data= (uint8_t*)malloc(pTempSectionHeader->mSectionSize);
        if(data == NULL)continue;
        lseek(fd, pTempSectionHeader->mSectionOffset, SEEK_SET);
        readCount = read(fd, data, pTempSectionHeader->mSectionSize);
        if(readCount != pTempSectionHeader->mSectionSize){
            loge("read symbol name string failed");
            free(data);
            continue;
        }
        if(pTempSectionHeader->mSectionType == SHT_STRTAB &&
           j != mElfHeader->mSectionHeaderStringHeaderIndex){
            logd("Symbol String index: %d,",j);
            mSymbolNameStrings = (char*)data;
        } else if(pTempSectionHeader->mSectionType == SHT_DYNSYM){
            mDynamicSymbolTableIndex = j;
        } else if(pTempSectionHeader->mSectionType == SHT_SYMTAB){
            mSymbolTableIndex = j;
        }
        mData[j] = data;
    }
/*Init all section content to data END*/
    mSectionNameStrings = (char*)mData[mElfHeader->mSectionHeaderStringHeaderIndex];
    logd("mDynamicSymbolTableIndex: %d, mSymbolTableIndex: %d",
         mDynamicSymbolTableIndex, mSymbolTableIndex);
    close(fd);
}

void SoInfo::parser32BitSo(uint64_t baseAddr, uint64_t fileSize) {
    Elf32_Ehdr *pEhdr = (Elf32_Ehdr*)baseAddr;
    mElfHeader = (struct ElfHeader_s*)malloc(sizeof(struct ElfHeader_s));
    if(mElfHeader == NULL){
        loge("Cannot malloc the memory, error: %s", strerror(errno));
        return;
    }
    memset(mElfHeader, 0x00, sizeof(struct ElfHeader_s));

    memcpy(mElfHeader->mElfIdent, pEhdr->e_ident, EI_NIDENT);

    mElfHeader->mElfType = pEhdr->e_type;
    mElfHeader->mElfMachine = pEhdr->e_machine;
    mElfHeader->mElfVersion = pEhdr->e_version;
    mElfHeader->mElfEntry = pEhdr->e_entry;
    mElfHeader->mProgramHeaderOffset = pEhdr->e_phoff;
    mElfHeader->mSectionHeaderOffset = pEhdr->e_shoff;
    mElfHeader->mElfFlags = pEhdr->e_flags;
    mElfHeader->mElfHeaderSize = pEhdr->e_ehsize;
    mElfHeader->mProgramHeaderSize = pEhdr->e_phentsize;
    mElfHeader->mProgramHeaderNum = pEhdr->e_phnum;
    mElfHeader->mSectionHeaderSize = pEhdr->e_shentsize;
    mElfHeader->mSectionHeaderNum = pEhdr->e_shnum;
    mElfHeader->mSectionHeaderStringHeaderIndex = pEhdr->e_shstrndx;

    mSectionCount = mElfHeader->mSectionHeaderNum;

/*Init Sectiont Name String content START*/
    Elf32_Shdr *pSectionNameSectionHeader =
            (Elf32_Shdr *)(baseAddr + mElfHeader->mSectionHeaderOffset
            +mElfHeader->mSectionHeaderSize * mElfHeader->mSectionHeaderStringHeaderIndex );
    uint64_t sectionNameStringSize = pSectionNameSectionHeader->sh_size;

    this->mSectionNameStrings = (char*)malloc(sectionNameStringSize);
    if(mSectionNameStrings == NULL){
        loge("Cannot malloc for section name string, err: %s",strerror(errno));
        return;
    }
    memset(mSectionNameStrings, 0x00, sectionNameStringSize);
    memcpy(mSectionNameStrings, (char*)(baseAddr + pSectionNameSectionHeader->sh_offset),
           sectionNameStringSize);
/*Init Sectiont Name String content END*/

/*cache all section headers START*/
    mSectionHeaders = (struct SectionHeader_s*)malloc(
            sizeof(struct SectionHeader_s) * mElfHeader->mSectionHeaderNum);
    if(mSectionHeaders == NULL){
        loge("Cannot malloc for section name string, err: %s",strerror(errno));
        return;
    }
    int sectionHeadersSize = mElfHeader->mSectionHeaderNum * mElfHeader->mSectionHeaderSize;
    memset(mSectionHeaders, 0x00, sectionNameStringSize);

    memcpy(mSectionHeaders, (char*)(baseAddr + mElfHeader->mSectionHeaderOffset),
           sectionHeadersSize);
/*cache all section headers END*/
}

void SoInfo::parser64BitSo(uint64_t baseAddr, uint64_t fileSize) {
    mElfHeader = (struct ElfHeader_s*)malloc(sizeof(struct ElfHeader_s));
    if(mElfHeader == NULL){
        loge("Cannot malloc the memory, error: %s", strerror(errno));
        return;
    }
    memset(mElfHeader, 0x00, sizeof(struct ElfHeader_s));

    memcpy(mElfHeader, (char*)baseAddr, sizeof(Elf64_Ehdr));
    dumpElfHeader();
    mSectionCount = mElfHeader->mSectionHeaderNum;


    /*Init Sectiont Name String content START*/
    struct SectionHeader_s *pSectionNameSectionHeader = (struct SectionHeader_s *)
            malloc(sizeof(struct SectionHeader_s));
    if(pSectionNameSectionHeader == NULL){
        loge("Cannot alloc memory for String name Section header, error: %s", strerror(errno));
        return;
    }
    memset(pSectionNameSectionHeader, 0x00,sizeof(struct SectionHeader_s));
    uint64_t sectionBase = baseAddr + mElfHeader->mSectionHeaderOffset +
                           mElfHeader->mSectionHeaderSize * mElfHeader->mSectionHeaderStringHeaderIndex;
    memcpy(pSectionNameSectionHeader, (char *)(sectionBase), sizeof(struct SectionHeader_s));

    uint64_t sectionNameStringSize = pSectionNameSectionHeader->mSectionSize;


    this->mSectionNameStrings = (char*)malloc(sectionNameStringSize);
    if(mSectionNameStrings == NULL){
        loge("Cannot malloc for mSectionNameStrings, err: %s",strerror(errno));
        return;
    }
    memset(mSectionNameStrings, 0x00, sectionNameStringSize);
    memcpy(mSectionNameStrings, (char*)(baseAddr + pSectionNameSectionHeader->mSectionOffset),
           sectionNameStringSize);

    if(pSectionNameSectionHeader)free(pSectionNameSectionHeader);
/*Init Sectiont Name String content END*/


/*cache all section headers START*/
    mSectionHeaders = (struct SectionHeader_s*)malloc(
            sizeof(struct SectionHeader_s) * mElfHeader->mSectionHeaderNum);
    if(mSectionHeaders == NULL){
        loge("Cannot malloc for mSectionHeaders, err: %s",strerror(errno));
        return;
    }
    int sectionHeadersSize = mElfHeader->mSectionHeaderNum * mElfHeader->mSectionHeaderSize;
    memset(mSectionHeaders, 0x00, sectionNameStringSize);

    memcpy(mSectionHeaders, (char*)(baseAddr + mElfHeader->mSectionHeaderOffset),
           sectionHeadersSize);
/*cache all section headers END*/
}

void SoInfo::dumpDynamicSymbolSection(){
    logd("dumpDynamicSymbolSection, mSectionCount: %d", mSectionCount);
    for (int i = 0; i < mSectionCount; ++i) {
        struct SectionHeader_s* tmpSectionHeader = &mSectionHeaders[i];
        if(tmpSectionHeader->mSectionType == SHT_DYNSYM || tmpSectionHeader->mSectionType == SHT_SYMTAB){
            int symbolCount = tmpSectionHeader->mSectionSize / tmpSectionHeader->mEntrySize;
            struct Symbol_s* content = (struct Symbol_s*)mData[i];
            logd("dumpDynamicSymbolSection, symbolCount: %d", symbolCount);
            for (int j = 0; j < symbolCount; ++j) {
                logd("==============================================");
                logd("Symbol Index: %d", j);
                dumpSymbol(&content[j]);
            }
        }
    }
}


void SoInfo::dumpSymbol(struct Symbol_s* symbol){
//    if(mSymbols == NULL) return;
    logd("Symbol Name: %s", (mSymbolNameStrings + symbol->mSymbolName));
    logd("Symbol Type: %s(0x%04x)", getSymbolTypeToString(ST_TYPE(symbol->mSymbolnfo)), ST_TYPE(symbol->mSymbolnfo));
    logd("Symbol Bind: %s(0x%04x)", getSymbolBindToString(ST_BIND(symbol->mSymbolnfo)), ST_BIND(symbol->mSymbolnfo));
}


void SoInfo::dumpRelocationSection(){
    struct Symbol_s* symbolData = NULL;
    if(mSymbolTableIndex > 0){
        symbolData = (struct Symbol_s*)mData[mSymbolTableIndex];
    } else if (mDynamicSymbolTableIndex > 0){
        symbolData = (struct Symbol_s*)mData[mDynamicSymbolTableIndex];
    }

    if(symbolData == NULL) return;


    for (int i = 0; i < mSectionCount; i++) {
        struct SectionHeader_s* pTempSectionHeader = &mSectionHeaders[i];
        if(pTempSectionHeader->mSectionType == SHT_REL){



        } else if (pTempSectionHeader->mSectionType == SHT_RELA){
            int relCount = pTempSectionHeader->mSectionSize / pTempSectionHeader->mEntrySize;
            struct RelocationA_s* relocations = (struct RelocationA_s*)mData[i];
            for (int j = 0; j < 500; ++j) {
                struct RelocationA_s* relocation = (relocations + j);
                uint64_t targetSymbolIndex = ELF64_R_SYM(relocation->mRelocationInfo);
                struct Symbol_s* symbol =symbolData + targetSymbolIndex;
                logd("==================================================");
                logd("Rel Index: %d, Rel Info: 0x%llx, symbolIndex: %d, ", j,
                     relocation->mRelocationInfo, targetSymbolIndex);
                logd("Target Offset: %llx, symbol name: %s",
                     relocation->mRelocationOffset,
                     (mSymbolNameStrings + symbol->mSymbolName));
            }
        }
    }
}

void SoInfo::dumpElfHeader(){
    if(mElfHeader == NULL)
        return;
    logd("Magic: 0x%02x %c%c%c", mElfHeader->mElfIdent[EI_MAG0],
          mElfHeader->mElfIdent[EI_MAG1],mElfHeader->mElfIdent[EI_MAG2],
          mElfHeader->mElfIdent[EI_MAG3]);

    logd("ElfType: 0x%04x", mElfHeader->mElfType);
    logd("ElfEntry: 0x%llx", mElfHeader->mElfEntry);

    logd("mProgramHeaderOffset: 0x%llx", mElfHeader->mProgramHeaderOffset);
    logd("mProgramHeaderSize: %d", mElfHeader->mProgramHeaderSize);
    logd("mProgramHeaderNum: %d", mElfHeader->mProgramHeaderNum);
    logd("mSectionHeaderOffset: 0x%llx", mElfHeader->mSectionHeaderOffset);
    logd("mEntrySize: %d", mElfHeader->mSectionHeaderSize);
    logd("mSectionHeaderNum: %d", mElfHeader->mSectionHeaderNum);
    logd("mElfFlags: 0x%04x", mElfHeader->mElfFlags);
    logd("mSectionHeaderStringHeaderIndex: %d", mElfHeader->mSectionHeaderStringHeaderIndex);
    logd("mElfHeaderSize: %d", mElfHeader->mElfHeaderSize);

}

void SoInfo::dumpSection(struct SectionHeader_s* pSection){
    if(pSection == NULL)return;

    logd("SectionName: %s", (pSection->mSectionName + mSectionNameStrings));
    logd("mSectionType: %s(0x%04x)", getSectionTypeToString(pSection->mSectionType), pSection->mSectionType);
    logd("mSectionFlags: %s(0x%04x)", getAttributeFlagToString(pSection->mSectionFlags), pSection->mSectionFlags);
    logd("mSectionAddr: 0x%08x", pSection->mSectionAddr);
    logd("mSectionOffset: 0x%08x", pSection->mSectionOffset);
    logd("mSectionSize: %d", pSection->mSectionSize);
    logd("mSectionLink: 0x%04x", pSection->mSectionLink);
    logd("mSectionInfo: 0x%04x", pSection->mSectionInfo);
    logd("mSectionAddrAlign: %d", pSection->mSectionAddrAlign);
    logd("mEntrySize: %d", pSection->mEntrySize);
}

void SoInfo::dumpSections(int type) {
    if(type < 0){
        if(mSectionHeaders == NULL)
            return;
        logd("mSectionCount: %d", mSectionCount);
        for (int i = 0; i < mSectionCount; ++i) {
            struct SectionHeader_s *pSectionHeader = &mSectionHeaders[i];
            logd("==========================================");
            logd("Section Index: %d", i);
            dumpSection(pSectionHeader );
        }
    } else {
        for (int i = 0; i < mSectionCount; ++i) {
            struct SectionHeader_s* tempSectionHeader = &mSectionHeaders[i];
            if(tempSectionHeader->mSectionType == type){
                dumpSection(tempSectionHeader);
            }
        }
    }
}

SoInfo::~SoInfo() {
    if(mElfHeader)free(mElfHeader);
    if(mSectionNameStrings)free(mSectionNameStrings);
    if(mSectionHeaders)free(mSectionHeaders);
    if(mSymbolNameStrings)free(mSymbolNameStrings);


#if defined(USE_RELA)
    if(mPltRelocationAs) free(mPltRelocationAs);
    if(mRelocationAs) free(mRelocationAs);
#else
    if(mPltRelocations) free(mPltRelocations);
    if(mRelocations) free(mRelocations);
#endif

}

