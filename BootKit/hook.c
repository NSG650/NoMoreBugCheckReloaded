#include "hook.h"

BYTE IoInitSystemOriginal[25] = { 0 };

NTSTATUS(*ZwDisplayString)(
    PUNICODE_STRING DisplayString
    );

VOID(*RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

extern EFI_RUNTIME_SERVICES* gRT;

VOID IoInitSystemHook()
{
#pragma warning (push)
#pragma warning (disable : 4152)
    ZwDisplayString = FindExport(gKernelBase, "ZwDisplayString");
    RtlInitUnicodeString = FindExport(gKernelBase, "RtlInitUnicodeString");
#pragma warning (pop)

    UNICODE_STRING message = { 0 };
    RtlInitUnicodeString(&message, L"[+] Hello World!\n");
    ZwDisplayString(&message);

    Overwrite((VOID*)IoInitSystem, IoInitSystemOriginal, 25);
    return;
}

VOID SetupIoInitSystemHook(UINT8* IoInitSystemPtr, VOID* HookFunc)
{
    Memcpy(&IoInitSystemOriginal, IoInitSystemPtr, 25);

    gRT->ConvertPointer(EFI_OPTIONAL_PTR, &HookFunc);

    UINT8 Patch[] =
    {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	    // mov  r10, IoInitSystemPtr
        0x41, 0x52,														// push r10	; Set IoInitSystemPtr as the return address
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	    // mov  r10, HookFunc
        0x41, 0xFF, 0xE2,                                               // jmp  r10
    };

    Overwrite(IoInitSystemPtr, Patch, 25);

    VOID* ThunkAddress = IoInitSystemPtr;
    gRT->ConvertPointer(EFI_OPTIONAL_PTR, &ThunkAddress);

    Overwrite(IoInitSystemPtr + 2, &ThunkAddress, 8);
    Overwrite(IoInitSystemPtr + 14, &HookFunc, 8);
}
