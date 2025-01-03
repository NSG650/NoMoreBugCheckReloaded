#include "util.h"
#include "nt.h"

extern BYTE KeBugCheckExOriginalBytes[13];
extern VOID(*KeBugCheckEx)(UINT32 BugCheckCode,
    UINT64 Code1,
    UINT64 Code2,
    UINT64 Code3,
    UINT64 Code4
);
extern VOID* gKernelBase;

VOID SetupKeBugCheckExHook(UINT8* KeBugCheckExPtr, VOID* HookFunc);
VOID KeBugCheckExHook(UINT32 BugCheckCode, UINT64 Code1, UINT64 Code2, UINT64 Code3, UINT64 Code4);
