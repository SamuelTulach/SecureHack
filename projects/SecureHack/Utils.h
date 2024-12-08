#pragma once

namespace Utils
{
	typedef enum _MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
		MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
		MemoryMappedFilenameInformation, // UNICODE_STRING
		MemoryRegionInformation, // MEMORY_REGION_INFORMATION
		MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
		MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
		MemoryImageInformation,
		MemoryRegionInformationEx,
		MemoryPrivilegedBasicInformation,
		MemoryEnclaveImageInformation,
		MemoryBasicInformationCapped
	} MEMORY_INFORMATION_CLASS;

    UINT64 FindPattern(PVOID baseAddress, UINT64 size, const char* pattern);
    UINT64 FindPatternImage(PVOID base, const char* pattern);
    DWORD GetPidByName(const wchar_t* processName);
    UINT64 GetModule(DWORD pid, const wchar_t* moduleName, DWORD* moduleSize);
    UINT64 GetMappedFile(DWORD pid, const wchar_t* fileName, DWORD* fileSize);
}