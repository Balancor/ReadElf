#include <iostream>
#include "hook_elf.h"
#include <elf.h>
#include "HMLog.h"
int main() {
    SoInfo* plibguiInfo = new SoInfo("../libutils.so",NULL, 0);
//    plibguiInfo->dumpSections(-1);
//    plibguiInfo->dumpSections(SHT_RELA);
    plibguiInfo->dumpDynamicSymbolSection();

}