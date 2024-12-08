#include "Global.h"

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))
UINT64 Utils::FindPattern(PVOID baseAddress, UINT64 size, const char* pattern)
{
    UINT8* firstMatch = nullptr;
    const char* currentPattern = pattern;

    UINT8* start = static_cast<UINT8*>(baseAddress);
    const UINT8* end = start + size;

    for (UINT8* current = start; current < end; current++)
    {
        const UINT8 byte = currentPattern[0]; if (!byte) return reinterpret_cast<UINT64>(firstMatch);
        if (byte == '\?' || *static_cast<UINT8*>(current) == GET_BYTE(byte, currentPattern[1]))
        {
            if (!firstMatch) firstMatch = current;
            if (!currentPattern[2]) return reinterpret_cast<UINT64>(firstMatch);
            ((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
        }
        else
        {
            currentPattern = pattern;
            firstMatch = nullptr;
        }
    }

    return 0;
}

UINT64 Utils::FindPatternImage(PVOID base, const char* pattern)
{
    UINT64 match = 0;

    PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<UINT64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
    const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
    for (SIZE_T i = 0; i < headers->FileHeader.NumberOfSections; ++i)
    {
        const PIMAGE_SECTION_HEADER section = &sections[i];
        if (*reinterpret_cast<UINT32*>(section->Name) == 'EGAP' || memcmp(section->Name, ".text", 5) == 0)
        {
            match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<UINT64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
            if (match)
                break;
        }
    }

    return match;
}

DWORD Utils::GetPidByName(const wchar_t* processName)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot || snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry))
    {
        do
        {
            if (!_wcsicmp(processEntry.szExeFile, processName))
            {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

UINT64 Utils::GetModule(DWORD pid, const wchar_t* moduleName, DWORD* moduleSize)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (!snapshot || snapshot == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &moduleEntry))
    {
        do
        {
            if (!_wcsicmp(moduleEntry.szModule, moduleName))
            {
                *moduleSize = moduleEntry.modBaseSize;
                CloseHandle(snapshot);
                return reinterpret_cast<UINT64>(moduleEntry.modBaseAddr);
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

EXTERN_C NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle,PVOID BaseAddress, Utils::MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

UINT64 Utils::GetMappedFile(DWORD pid, const wchar_t* fileName, DWORD* fileSize)
{
    const HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!processHandle || processHandle == INVALID_HANDLE_VALUE)
        return 0;

    uint64_t currentAddress = 0;
    MEMORY_BASIC_INFORMATION memoryInformation;

    while (VirtualQueryEx(processHandle, reinterpret_cast<void*>(currentAddress), &memoryInformation, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        if (memoryInformation.Type == MEM_MAPPED || memoryInformation.Type == MEM_IMAGE)
        {
            constexpr size_t bufferSize = 1024;
            void* buffer = malloc(bufferSize);

            size_t bytesOut;
            const NTSTATUS status = NtQueryVirtualMemory(processHandle, memoryInformation.BaseAddress, MemoryMappedFilenameInformation, buffer, bufferSize, &bytesOut);
            if (status == 0)
            {
                const UNICODE_STRING* stringBuffer = static_cast<UNICODE_STRING*>(buffer);
                if (wcsstr(stringBuffer->Buffer, fileName) && !wcsstr(stringBuffer->Buffer, L".mui"))
                {
                    *fileSize = static_cast<DWORD>(memoryInformation.RegionSize);
                    free(buffer);
                    CloseHandle(processHandle);
                    return reinterpret_cast<uint64_t>(memoryInformation.BaseAddress);
                }
            }

            free(buffer);
        }

        currentAddress = reinterpret_cast<uint64_t>(memoryInformation.BaseAddress) + memoryInformation.RegionSize;
    }

    CloseHandle(processHandle);
    return 0;
}

