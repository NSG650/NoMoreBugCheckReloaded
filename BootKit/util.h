#pragma once
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include "nt.h"

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (UINT64)(&((type *)0)->field)))


VOID* GetLoadedModuleBase(const CHAR16* ModName);

UINT32* FindExportEntry(VOID* Module, const CHAR8* RoutineName);
VOID* FindExport(VOID* Module, const CHAR8* RoutineName);

UINT32* FindExportEntryByOrdinal(VOID* Module, UINT16 Ordinal);
VOID* FindExportByOrdinal(VOID* Module, UINT16 Ordinal);


KLDR_DATA_TABLE_ENTRY* GetKernelModuleFromList(LIST_ENTRY* Head, const CHAR16* ModuleName);

VOID* FindPattern(VOID* StartAddress, UINTN SearchLimit, UINT8* Pattern, UINTN PatternSize, UINT8* Mask);

void Memcpy(const VOID* Destination, const VOID* Source, UINTN Length);
void Overwrite(const VOID* Destination, const VOID* Source, UINTN Length);
