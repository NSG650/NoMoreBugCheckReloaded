extern CONST UINT32 _gUefiDriverRevision = 0;
CHAR8* gEfiCallerBaseName = "ShellSample";

CONST UINT8  _gDriverUnloadImageCount = 1;

EFI_STATUS EFIAPI UefiUnload(IN EFI_HANDLE ImageHandle)
{
    return EFI_SUCCESS;
}