//
// Created by guoguo on 18-3-31.
//

#ifndef ELFHOOK_HOOK_ELF_H
#define ELFHOOK_HOOK_ELF_H

#include <cstdint>
#include <list>
#include <elf.h>
using namespace std;

#define SOINF_NAME_LEN 128
typedef void (*linker_function_t)();

typedef uint64_t HMElf_Addr;
typedef uint16_t HMElf_Half;
typedef int16_t  HMElf_SHalf;
typedef uint16_t HMElf_Off;
typedef int32_t  HMElf_Sword;
typedef uint32_t HMElf_Word;
typedef uint64_t HMElf_Xword;
typedef int64_t  HMElf_Sxword;

struct ElfHeader_s{
    unsigned char mElfIdent[EI_NIDENT];
    uint16_t mElfType;
    uint16_t mElfMachine;
    uint32_t mElfVersion;
    uint64_t mElfEntry;
    uint64_t  mProgramHeaderOffset;
    uint64_t  mSectionHeaderOffset;
    uint32_t mElfFlags;
    uint16_t  mElfHeaderSize;

    uint16_t mProgramHeaderSize;
    uint16_t mProgramHeaderNum;

    uint16_t mSectionHeaderSize;
    uint16_t mSectionHeaderNum;

    uint16_t mSectionHeaderStringHeaderIndex;
};

struct ProgramHeader_s{
    HMElf_Word mProgramType;
    HMElf_Word mProgramFlags;
    HMElf_Off  mProgramOffset;
    HMElf_Addr mProgramVAddr;
    HMElf_Addr mProgramPAddr;
    HMElf_Xword mProgramFileSize;
    HMElf_Xword mProgramMemSize;
    HMElf_Xword mProgramAlign;
};

struct SectionHeader_s{
    uint32_t  mSectionName;
    uint32_t  mSectionType;
    uint64_t  mSectionFlags;
    uint64_t  mSectionAddr;
    uint64_t  mSectionOffset;
    uint64_t  mSectionSize;
    uint32_t  mSectionLink;
    uint32_t  mSectionInfo;
    uint64_t  mSectionAddrAlign;
    uint64_t  mEntrySize;
};

struct Symbol_s{
    HMElf_Word mSymbolName;
    unsigned char mSymbolnfo;
    unsigned char mSymbolOther;
    HMElf_Half mSymbolIndex;
    HMElf_Addr  mSymbolValue;
    HMElf_Xword mSymbolSize;
};

#define ST_BIND(info)          ((info) >> 4)
#define ST_TYPE(info)          ((info) & 0xf)
#define ST_INFO(bind, type)    (((bind)<<4)+((type)&0xf))

struct Relocation_s{
    HMElf_Addr mRelocationOffset;
    HMElf_Xword mRelocationInfo;
};

struct RelocationA_s{
    HMElf_Addr mRelocationOffset;
    HMElf_Xword mRelocationInfo;
    HMElf_Sxword mRelocationAddend;
};

struct Dynamic_s{
    HMElf_Sxword mDynamicTag;
    union {
        HMElf_Xword mDynamicValue;
        HMElf_Addr  mDynmicPtr;
    }dynamic_un;
};

struct LinkMap_s {
  HMElf_Addr mLinkAddr;
  char* mLinkName;
  Dynamic_s* mLinkDynamic;
  struct LinkMap_s* mNexLinkMap;
  struct LinkMap_s* mPrevLinkMap;
};

class SoInfo{
private:
    char soName[SOINF_NAME_LEN];
    bool is64Bit;
    uint32_t mFlags;
    struct ElfHeader_s* mElfHeader;
    struct SectionHeader_s* mSectionHeaders;
    int mSectionCount;

    uint8_t **mData;
    void freeData();


    char* mSectionNameStrings;
    char* mSymbolNameStrings;

    int mSymbolTableIndex;
    int mDynamicSymbolTableIndex;



    size_t mBucketNum;
    size_t mChainNum;

    uint32_t *mBucket;
    uint32_t *mChain;

    HMElf_Addr ** mPltGot;
#if defined(USE_RELA)
    RelocationA_s* mPltRelocationAs;
    size_t mPltRelocationACount;

    RelocationA_s* mRelocationAs;
    size_t mRelocationACount;
#else
    Relocation_s* mPltRelocations;
    size_t mPltRelocationCount;
    Relocation_s* mRelocations;
    size_t mRelocationCount;
#endif
    void collectRelocations();


    linker_function_t* mPreInitFuncs;
    size_t mPreInitFuncCount;

    linker_function_t* mInitFuncs;
    size_t mInitFuncCount;

    linker_function_t* mFiniFuncs;
    size_t mFiniFuncCount;

    linker_function_t mInitFunc;
    linker_function_t mFiniFunc;

    size_t mRefCount;

public:
    const ProgramHeader_s* mProgramHeader;
    size_t mProgramNum;
    HMElf_Addr mElfEntryAddr;
    HMElf_Addr mElfBaseAddr;
    size_t mSoSize;

    Dynamic_s* mDynamic;
    SoInfo* mNextSoInfo;

    LinkMap_s mLinkMapHead;

    bool mConstructorCalled;

    HMElf_Addr  mLoadBias;

    bool hasTextTelocation;
    bool hasDynamicSymbol;

    uint32_t mVersion;

    list<SoInfo> mDepenceSoInfos;
    list<SoInfo> mDependencedSoInfo;

    SoInfo* mLocalGroupRoot;



public:
    SoInfo(const char* name, const struct stat* file_stat,
        off64_t file_offset);
    ~SoInfo();

    void parser32BitSo(uint64_t baseAddr, uint64_t fileSize);
    void parser64BitSo(uint64_t baseAddr, uint64_t fileSize);
    void parser32BitSo(const char* libPath);
    void parser64BitSo(const char* libPath);
    void call_constructor();
    void call_destructor();

    void call_pre_init_constructor();

    bool prelink_image();

    bool link_image();

    bool protect_relro();

    void addChild(SoInfo* child);
    void removeAllLinks();

    list<SoInfo>& getChildren();
    const list<SoInfo>& getChildren()const ;

    list<SoInfo>& getParents();

    bool findSymbolByName(const char* name, Symbol_s** pSymbols) const ;

    Symbol_s* findSymbolByAddress(const void* addr);
    HMElf_Addr resolveSymbolAddress(const Symbol_s* s)const;

    const char* getString(HMElf_Word index)const;

    bool canUnload()const ;
    void incrementRefCount();
    size_t decrementRefCount();

    SoInfo* getLocalGroupRoot();

    void setSoName(const char* soname);
    const char* getSoname()const;


    bool elfLookup(const char* name, uint32_t* symbolIndex) const;

    Symbol_s* elfAddrLookup(const void* addr);
    bool gunLookup(const char* symbolname, uint32_t* symbolIndex)const ;

    void callFunc(const char* funcName, linker_function_t* funcs);
    void callArray(const char* arrayName, linker_function_t* functions,
    size_t count);


    //if type is -1, dump all sections
    void dumpElfHeader();
    void dumpSections(int type);
    void dumpSection(struct SectionHeader_s* pSection);
    void dumpRelocationSection();
    void dumpRelocation();
    void dumpDynamicSymbolSection();
    void dumpSymbol(struct Symbol_s* symbol);

};

#endif //ELFHOOK_HOOK_ELF_H
