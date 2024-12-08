#pragma once

UINT64 FindPattern(VOID* baseAddress, UINT64 size, const CHAR8* pattern);
UINT64 FindPatternImage(VOID* base, const CHAR8* pattern);
UINT64 GetExport(VOID* base, const CHAR8* functionName);
VOID Sleep(UINTN seconds);
UINTN GetCurrentImageSize(VOID);
VOID* InternalCopyMemory(VOID* dest, const VOID* src, const UINTN count);