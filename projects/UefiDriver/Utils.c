#include "Global.h"

#define IN_RANGE(x, a, b) ((x) >= (a) && (x) <= (b))
#define GET_BITS(x) (IN_RANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xA) : (IN_RANGE(x, '0', '9') ? (x - '0') : 0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))

UINT64 FindPattern(VOID* baseAddress, const UINT64 size, const CHAR8* pattern)
{
    UINT8* firstMatch = NULL;
    const CHAR8* currentPattern = pattern;

    UINT8* start = (UINT8*)baseAddress;
    UINT8* end = start + size;

    for (UINT8* current = start; current < end; current++)
    {
        UINT8 byte = currentPattern[0];
        if (!byte) return (UINT64)firstMatch;
        if (byte == '?' || *current == GET_BYTE(byte, currentPattern[1]))
        {
            if (!firstMatch) firstMatch = current;
            if (!currentPattern[2]) return (UINT64)firstMatch;
            currentPattern += (byte == '?') ? 2 : 3;
        }
        else
        {
            currentPattern = pattern;
            firstMatch = NULL;
        }
    }

    return 0;
}

UINT64 FindPatternImage(VOID* base, const CHAR8* pattern)
{
    UINT64 match = 0;

    PIMAGE_NT_HEADERS64 headers = (PIMAGE_NT_HEADERS64)((UINT64)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
    for (INTN i = 0; i < headers->FileHeader.NumberOfSections; ++i)
    {
        PIMAGE_SECTION_HEADER section = &sections[i];
        if (*(UINT32*)section->Name == 'EGAP' || CompareMem(section->Name, ".text", 5) == 0)
        {
            match = FindPattern((void*)((UINT64)base + section->VirtualAddress), section->Misc.VirtualSize, pattern);
            if (match)
                break;
        }
    }

    return match;
}

UINT64 GetExport(VOID* base, const CHAR8* functionName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((UINT64)base + dosHeader->e_lfanew);

    UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportsRva)
        return 0;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((UINT64)base + exportsRva);
    UINT32* nameRva = (UINT32*)((UINT64)base + exports->AddressOfNames);

    for (UINT32 i = 0; i < exports->NumberOfNames; ++i)
    {
        CHAR8* func = (CHAR8*)((UINT64)base + nameRva[i]);
        if (AsciiStrCmp(func, functionName) == 0)
        {
            UINT32* funcRva = (UINT32*)((UINT64)base + exports->AddressOfFunctions);
            UINT16* ordinalRva = (UINT16*)((UINT64)base + exports->AddressOfNameOrdinals);

            return (UINT64)base + funcRva[ordinalRva[i]];
        }
    }

    return 0;
}

VOID Sleep(const UINTN seconds)
{
    gBS->Stall(seconds * 1000 * 1000);
}

extern IMAGE_DOS_HEADER __ImageBase;
UINTN GetCurrentImageSize(VOID)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&__ImageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT8*)dosHeader + dosHeader->e_lfanew);
    return ntHeaders->OptionalHeader.SizeOfImage + EFI_PAGE_SIZE;
}

VOID* InternalCopyMemory(VOID* dest, const VOID* src, const UINTN count)
{
    UINT8* d = (UINT8*)dest;
    const UINT8* s = (const UINT8*)src;

    for (UINTN i = 0; i < count; i++)
        d[i] = s[i];

    return dest;
}
