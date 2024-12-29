#include "util.h"
#include "nt.h"

extern BYTE IoInitSystem_Original[25];
extern UINT32(*IoInitSystem)();
extern VOID* gKernelBase;

VOID SetupIoInitSystemHook(UINT8* _ioInitSystem, VOID* HookFunc);
VOID IoInitSystemHook();