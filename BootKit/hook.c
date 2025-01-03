#include "hook.h"

BYTE KeBugCheckExOriginalBytes[13] = { 0 };

extern EFI_RUNTIME_SERVICES* gRT;

VOID(*DbgPrint)(
    INT8* Format,
    ...
);

NTSTATUS(*KeDelayExecutionThread)(
    KPROCESSOR_MODE WaitMode,
    BOOLEAN         Alertable,
    PLARGE_INTEGER  Interval
);

HANDLE(*PsGetCurrentProcessId)();
HANDLE(*PsGetCurrentThreadId)();

#define IRQL_NOT_GREATER_OR_EQUAL 0x9
#define IRQL_NOT_LESS_OR_EQUAL 0xA
#define KMODE_EXCEPTION_NOT_HANDLED 0x1E
#define SYSTEM_THREAD_EXCEPTION_NOT_HANDLED 0x7E
#define SYSTEM_SERVICE_EXCEPTION 0x3B

VOID KeBugCheckExHook(UINT32 BugCheckCode, UINT64 Code1, UINT64 Code2, UINT64 Code3, UINT64 Code4)
{
    // This sounds so wrong...
    UINT32 BugChecksThatCanBeSafelyIgnored[] = { SYSTEM_THREAD_EXCEPTION_NOT_HANDLED, SYSTEM_SERVICE_EXCEPTION, IRQL_NOT_GREATER_OR_EQUAL, IRQL_NOT_LESS_OR_EQUAL, KMODE_EXCEPTION_NOT_HANDLED };
    UINT8 CanWeIgnoreThis = 0;
    for (INT32 i = 0; i < 5; i++) {
        if (BugCheckCode == BugChecksThatCanBeSafelyIgnored[i]) {
            CanWeIgnoreThis = 1;
            break;
        }
    }

    // Check if it was thrown by the kernel or driver
    if (CanWeIgnoreThis) {
        // This was called by the kernel or a core system process.
        // This is a bad way to check but I am in a hurry.
        if (PsGetCurrentProcessId() <= 480) {
            CanWeIgnoreThis = 0;
        }
    }

    // CHECK THE BUG
    if (!CanWeIgnoreThis) {
        Overwrite((VOID*)KeBugCheckEx, KeBugCheckExOriginalBytes, 13);
        KeBugCheckEx(BugCheckCode, Code1, Code2, Code3, Code4);
    }

    DbgPrint("[*] KeBugCheckEx was called by Process %d, thread id %d\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
    DbgPrint("[*] KeBugCheckEx(0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", BugCheckCode,
        Code1, Code2, Code3, Code4);
    LARGE_INTEGER Delay;

    Delay.u.LowPart = 0;
    Delay.u.HighPart = 0x80000000;

    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

VOID SetupKeBugCheckExHook(UINT8* KeBugCheckExPtr, VOID* HookFunc)
{
#pragma warning (push)
#pragma warning (disable : 4152)
    DbgPrint = FindExport(gKernelBase, "DbgPrint");
    KeDelayExecutionThread = FindExport(gKernelBase, "KeDelayExecutionThread");
    PsGetCurrentProcessId = FindExport(gKernelBase, "PsGetCurrentProcessId");
    PsGetCurrentThreadId = FindExport(gKernelBase, "PsGetCurrentThreadId");
#pragma warning (pop)
    Memcpy(&KeBugCheckExOriginalBytes, KeBugCheckExPtr, 13);

    gRT->ConvertPointer(EFI_OPTIONAL_PTR, &HookFunc);

    UINT8 Patch[] =
    {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, address
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    Overwrite(KeBugCheckExPtr, Patch, 13);

    VOID* ThunkAddress = KeBugCheckExPtr;
    gRT->ConvertPointer(EFI_OPTIONAL_PTR, &ThunkAddress);

    Overwrite(KeBugCheckExPtr + 2, &HookFunc, 8);
}
