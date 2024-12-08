#include "Global.h"

#pragma warning(disable : 4146)

#define P2ALIGNUP(x, align) (-(-(x) & -(align)))
UINT64 AddSection(const UINT64 imageBase, const CHAR8* sectionName, const UINT32 virtualSize, const UINT32 characteristics)
{
    const EFI_IMAGE_DOS_HEADER* dosHeader = (EFI_IMAGE_DOS_HEADER*)imageBase;
    EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT64)imageBase + dosHeader->e_lfanew);

    const UINT16 sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
    EFI_IMAGE_FILE_HEADER* fileHeader = &(ntHeaders->FileHeader);

    EFI_IMAGE_SECTION_HEADER* firstSectionHeader = (EFI_IMAGE_SECTION_HEADER*)(((UINT64)fileHeader) + sizeof(EFI_IMAGE_FILE_HEADER) + sizeOfOptionalHeader);

    const UINT32 numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    const UINT32 sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    const UINT32 fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

    EFI_IMAGE_SECTION_HEADER* newSectionHeader = &firstSectionHeader[numberOfSections];
    const EFI_IMAGE_SECTION_HEADER* lastSectionHeader = &firstSectionHeader[numberOfSections - 1];

    CopyMem(&newSectionHeader->Name, sectionName, AsciiStrLen(sectionName));
    newSectionHeader->Misc.VirtualSize = virtualSize;
    newSectionHeader->VirtualAddress = P2ALIGNUP(lastSectionHeader->VirtualAddress + lastSectionHeader->Misc.VirtualSize, sectionAlignment);

    newSectionHeader->SizeOfRawData = P2ALIGNUP(virtualSize, fileAlignment);
    newSectionHeader->Characteristics = characteristics;

    newSectionHeader->PointerToRawData = (UINT32)(lastSectionHeader->PointerToRawData + lastSectionHeader->SizeOfRawData);

    ++ntHeaders->FileHeader.NumberOfSections;
    ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(newSectionHeader->VirtualAddress + newSectionHeader->Misc.VirtualSize, sectionAlignment);

    return imageBase + newSectionHeader->VirtualAddress;
}

extern IMAGE_DOS_HEADER __ImageBase;
VOID ProcessHvImage(const UINT64 imageBase)
{
    const UINT32 currentImageSize = (UINT32)GetCurrentImageSize();
    const UINT64 section = AddSection(imageBase, ".uwu", currentImageSize, SECTION_RWX);
    DebugFormat("Added new section at 0x%p\n", section);

    /*
     * IDA for some reason does not detect this particular routine as code, but as data.
     * Search for the vmrun instruction but as a byte sequence: 0F 01 D8.
     */
    const UINT64 scan = FindPatternImage((VOID*)imageBase, "E8 ? ? ? ? 48 89 04 24 E9");
    if (!scan)
    {
        DebugFormat("Failed to find pattern\n");
        return;
    }

    const UINT64 currentImageBase = (UINT64)&__ImageBase;
    const UINT64 targetFunction = (UINT64)HookedVmExitHandler;
    const UINT64 offset = targetFunction - currentImageBase;
    const UINT64 remoteFunction = section + offset;

    const UINT64 originalBase = scan + 5;
    const INT32 originalOffset = *(INT32*)(scan + 1);
    const UINT64 originalFunction = originalBase + originalOffset;
    const INT32 newOffset = (INT32)(remoteFunction - originalBase);

    OriginalOffsetFromHook = (INT32)(originalFunction - remoteFunction);

    DebugFormat("Found function call at 0x%p:\n", scan);
    DebugFormat(" - Original offset: %d\n", originalOffset);
    DebugFormat(" - Original function: 0x%p\n", originalFunction);
    DebugFormat(" - New offset: %d\n", newOffset);
    DebugFormat(" - New function: 0x%p\n", remoteFunction);
    DebugFormat(" - Hook offset: %d\n", OriginalOffsetFromHook);

    *(INT32*)(scan + 1) = newOffset;

    CopyMem((VOID*)section, (VOID*)&__ImageBase, currentImageSize);
    DebugFormat("Remapped current image to 0x%p with size %u\n", section, currentImageSize);
}