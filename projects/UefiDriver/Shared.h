#pragma once

#define CPUID_BACKDOOR 0xaabbccdd12345
#define CPUID_RETURN_VALUE 0x123456789

#define COMMAND_CHECK_PRESENCE 1
#define COMMAND_INIT_MEMORY 2
#define COMMAND_GET_CR3 3
#define COMMAND_VIRTUAL_MEMORY_COPY 4
#define COMMAND_SECUREKERNEL_INFO 5
#define COMMAND_READ_PHYSICAL 6
#define COMMAND_ENCLAVE_INFO 7

typedef struct _VIRTUAL_MEMORY_COPY
{
    UINT64 SourceCr3;
    UINT64 SourceAddress;
    UINT64 DestinationCr3;
    UINT64 DestinationAddress;
    UINT64 Size;
} VIRTUAL_MEMORY_COPY;

typedef struct _READ_PHYSICAL
{
    UINT64 PhysicalSourceAddress;
    UINT64 VirtualDestinationAddress;
    UINT64 Cr3;
    UINT64 Size;
} READ_PHYSICAL;

typedef struct _SECUREKERNEL_DATA
{
    UINT64 BasePhysical;
    UINT64 BaseVirtual;
    UINT64 Size;
    UINT64 CR3;
} SECUREKERNEL_DATA;

typedef struct _ENCLAVE_DATA
{
    UINT64 TotalCalls;
    UINT64 LastRip;
    UINT64 LastCR3;
} ENCLAVE_DATA;

typedef struct COMMAND_DATA
{
    union
    {
        VIRTUAL_MEMORY_COPY VirtualMemoryCopy;
        READ_PHYSICAL ReadPhysical;
        SECUREKERNEL_DATA SecureKernelData;
        ENCLAVE_DATA EnclaveData;
    };
} COMMAND_DATA;