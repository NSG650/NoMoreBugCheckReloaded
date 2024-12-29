#include <intrin.h>
#include "util.h"
#include "nt.h"

UINT64 AsciiToInt(CHAR8* ascii)
{
    UINT64 retInt = 0;
    while (*ascii)
    {
        if (*ascii <= '0' || *ascii >= '9')
            return 0;
        retInt *= 10;
        retInt += *ascii - '0';
        ascii++;
    }
    return retInt;
}

CHAR16 WideCharToLower(CHAR16 c)
{
    if (c >= 'A' && c <= 'Z') return c += ('a' - 'A');
    else return c;
}

INTN WCSNICMP(const CHAR16* First, const CHAR16* Second, UINTN Length)
{
    for (int i = 0; i < Length && First[i] && Second[i]; ++i)
        if (WideCharToLower(First[i]) != WideCharToLower(Second[i]))
            return First[i] - Second[i];

    return 0;
}


UINT32* FindExportEntry(VOID* Module, const CHAR8* RoutineName)
{
    PIMAGE_DOS_HEADER dos = Module;
    if (dos->e_magic != 0x5A4D)
        return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)Module + dos->e_lfanew);
    UINT32 exportsRVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!exportsRVA)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)Module + exportsRVA);
    UINT32* nameTable = (UINT32*)((UINT8*)Module + exportDirectory->AddressOfNames);


    for (int lower = 0, upper = exportDirectory->NumberOfNames - 1; upper >= lower;)
    {
        int i = (upper + lower) / 2;
        const CHAR8* funcName = (CHAR8*)((UINT8*)Module + nameTable[i]);
        INTN diff = AsciiStrCmp(RoutineName, funcName);
        if (diff > 0)
            lower = i + 1;
        else if (diff < 0)
            upper = i - 1;
        else
        {
            UINT32* exportFuncTable = (UINT32*)((UINT8*)Module + exportDirectory->AddressOfFunctions);
            UINT16* ordinalTable = (UINT16*)((UINT8*)Module + exportDirectory->AddressOfNameOrdinals);

            UINT16 index = ordinalTable[i];
            if (exportFuncTable[index] < nt->OptionalHeader.DataDirectory[0].VirtualAddress ||
                exportFuncTable[index] > nt->OptionalHeader.DataDirectory[0].VirtualAddress + nt->OptionalHeader.DataDirectory[0].Size)
                return exportFuncTable + index;
            else
            {
                CHAR16 buffer[260];
                CHAR8* forwarderRVAString = (CHAR8*)Module + exportFuncTable[index];
                UINT16 dllNameLen;
                for (dllNameLen = 0; dllNameLen < 259; ++dllNameLen)
                    if (forwarderRVAString[dllNameLen] == '.') break;
                for (int j = 0; j < dllNameLen; ++j)
                    buffer[j] = (CHAR16)forwarderRVAString[j];
                buffer[dllNameLen] = L'\0';
                if (forwarderRVAString[dllNameLen + 1] == '#')
                    return FindExportEntryByOrdinal(GetLoadedModuleBase(buffer), (UINT16)AsciiToInt(&forwarderRVAString[dllNameLen + 2]));
                else
                    return FindExportEntry(GetLoadedModuleBase(buffer), forwarderRVAString + dllNameLen + 1);
            }
        }
    }
    return NULL;
}

UINT32* FindExportEntryByOrdinal(VOID* Module, UINT16 Ordinal)
{
    PIMAGE_DOS_HEADER dos = Module;
    if (dos->e_magic != 0x5A4D)
        return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)Module + dos->e_lfanew);
    UINT32 exportsRVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!exportsRVA)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)Module + exportsRVA);
    UINT16 index = Ordinal - (UINT16)exportDirectory->Base;

    UINT32* exportFuncTable = (UINT32*)((UINT8*)Module + exportDirectory->AddressOfFunctions);
    if (exportFuncTable[index] < nt->OptionalHeader.DataDirectory[0].VirtualAddress ||
        exportFuncTable[index] > nt->OptionalHeader.DataDirectory[0].VirtualAddress + nt->OptionalHeader.DataDirectory[0].Size)
        return exportFuncTable + index;
    else
    {
        CHAR16 buffer[260];
        CHAR8* forwarderRVAString = (CHAR8*)Module + exportFuncTable[index];
        UINT16 dllNameLen;
        for (dllNameLen = 0; dllNameLen < 259; ++dllNameLen)
            if (forwarderRVAString[dllNameLen] == '.') break;
        for (int i = 0; i < dllNameLen; ++i)
            buffer[i] = (CHAR16)forwarderRVAString[i];
        buffer[dllNameLen] = L'\0';
        if (forwarderRVAString[dllNameLen + 1] == '#')
            return FindExportEntryByOrdinal(GetLoadedModuleBase(buffer), (UINT16)AsciiToInt(&forwarderRVAString[dllNameLen + 2]));
        else
            return FindExportEntry(GetLoadedModuleBase(buffer), forwarderRVAString + dllNameLen + 1);
    }
}

VOID* FindExport(VOID* Module, const CHAR8* RoutineName)
{
    UINT32* entry = FindExportEntry(Module, RoutineName);
    if (!entry)
        return NULL;
    return (VOID*)((UINT8*)Module + *entry);
}

VOID* FindExportByOrdinal(VOID* Module, UINT16 Ordinal)
{
    UINT32* entry = FindExportEntryByOrdinal(Module, Ordinal);
    if (!entry)
        return NULL;
    return (VOID*)((UINT8*)Module + *entry);
}


extern VOID* gKernelBase;
VOID* GetLoadedModuleBase(const CHAR16* ModName)
{
    static LIST_ENTRY* PsLoadedModuleList;
    if (!PsLoadedModuleList)
        PsLoadedModuleList = FindExport(gKernelBase, "PsLoadedModuleList");

    KLDR_DATA_TABLE_ENTRY* module = GetKernelModuleFromList(PsLoadedModuleList, ModName);
    if (!module)
        return NULL;
    return module->ModuleBase;
}

VOID* FindPattern(VOID* StartAddress, UINTN SearchLimit, UINT8* Pattern, UINTN PatternSize, UINT8* Mask) {
    UINT8* CurrentAddress = (UINT8*)StartAddress;
    UINT8* EndAddress = CurrentAddress + SearchLimit;

    for (UINTN i = 0; CurrentAddress + i + PatternSize <= EndAddress; i++)
    {
        BOOLEAN Match = TRUE;
        for (UINTN j = 0; j < PatternSize; j++)
        {
            if (Mask[j] == 0x00 && CurrentAddress[i + j] != Pattern[j])
            {
                Match = FALSE;
                break;
            }
        }

        if (Match) return (VOID*)(CurrentAddress + i);
    }

    return NULL;
}


// Thanks NSG
KLDR_DATA_TABLE_ENTRY* GetKernelModuleFromList(LIST_ENTRY* Head, const CHAR16* ModuleName)
{
    for (LIST_ENTRY* it = Head->ForwardLink; it && it != Head; it = it->ForwardLink)
    {
        KLDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(it, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!WCSNICMP(entry->BaseModuleName.Buffer, ModuleName, entry->BaseModuleName.Length))
        {
            return entry;
        }
    }
    return NULL;
}

#pragma warning (push)
#pragma warning (disable : 4090)
void Memcpy(const VOID* Destination, const VOID* Source, UINTN Length)
{
    __movsb(Destination, Source, Length);
}
#pragma warning (pop)

void Overwrite(const VOID* Destination, const VOID* Source, UINTN Length)
{
    UINT64 interruptsEnabled = __readeflags() & 0x200;
    if (interruptsEnabled)
        _disable();
    UINT64 cr4 = __readcr4();
    __writecr4(cr4 & ~0x800000ull);
    UINT64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ull);

    Memcpy(Destination, Source, Length);

    __writecr0(cr0);
    __writecr4(cr4);
    if (interruptsEnabled)
        _enable();
}
