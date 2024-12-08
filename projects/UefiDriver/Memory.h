#pragma once

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

#pragma warning(disable : 4201)

#pragma pack(push, 1)
typedef union VIRT_ADDR_
{
    UINT64 Value;
    void* Pointer;
    struct
    {
        UINT64 Offset : 12;
        UINT64 PtIndex : 9;
        UINT64 PdIndex : 9;
        UINT64 PdptIndex : 9;
        UINT64 Pml4Index : 9;
        UINT64 Reserved : 16;
    };
} VIRTUAL_ADDRESS;

/*typedef union CR3_
{
    UINT64 Value;
    struct
    {
        UINT64 Ignored1 : 3;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Ignored2 : 7;
        UINT64 Pml4 : 40;
        UINT64 Reserved : 12;
    };
} PTE_CR3;

typedef union PML4E_
{
    UINT64 Value;
    struct
    {
        UINT64 Present : 1;
        UINT64 Rw : 1;
        UINT64 User : 1;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Ignored1 : 1;
        UINT64 Reserved1 : 1;
        UINT64 Ignored2 : 4;
        UINT64 Pdpt : 40;
        UINT64 Ignored3 : 11;
        UINT64 Xd : 1;
    };
} PML4E;

typedef union PDPTE_
{
    UINT64 Value;
    struct
    {
        UINT64 Present : 1;
        UINT64 Rw : 1;
        UINT64 User : 1;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 PageSize : 1;
        UINT64 Ignored2 : 4;
        UINT64 Pd : 40;
        UINT64 Ignored3 : 11;
        UINT64 Xd : 1;
    };
} PDPTE;

typedef union PDE_
{
    UINT64 Value;
    struct
    {
        UINT64 Present : 1;
        UINT64 Rw : 1;
        UINT64 User : 1;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 PageSize : 1;
        UINT64 Ignored2 : 4;
        UINT64 Pt : 40;
        UINT64 Ignored3 : 11;
        UINT64 Xd : 1;
    };
} PDE;

typedef union PTE_
{
    UINT64 Value;
    VIRTUAL_ADDRESS VirtualAddress;
    struct
    {
        UINT64 Present : 1;
        UINT64 Rw : 1;
        UINT64 User : 1;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 Pat : 1;
        UINT64 Global : 1;
        UINT64 Ignored1 : 3;
        UINT64 PageFrame : 40;
        UINT64 Ignored3 : 11;
        UINT64 Xd : 1;
    };
} PTE;*/
#pragma pack(pop)

#define SELF_REF_PML4_IDX 510
#define MAPPING_PML4_IDX 100

#define MAPPING_ADDRESS_BASE 0x0000327FFFE00000
#define SELF_REF_PML4 0xFFFFFF7FBFDFE000

#define EPT_LARGE_PDPTE_OFFSET(_) (((u64)(_)) & ((0x1000 * 0x200 * 0x200) - 1))
#define EPT_LARGE_PDE_OFFSET(_) (((u64)(_)) & ((0x1000 * 0x200) - 1))

enum MapType
{
    MapSource,
    MapDestination
};

typedef struct _SECUREKERNEL_INFO
{
    UINT64 BaseAddressPhysical;
    UINT64 BaseAddressVirtual;
    UINTN Size;
    UINT64 CR3;
} SECUREKERNEL_INFO;

typedef struct _ENCLAVE_INFO
{
    UINTN TotalCalls;
    UINT64 LastRip;
    UINT64 LastCR3;
} ENCLAVE_INFO;

UINT64 MemoryGetMapVirtual(UINT16 offset, enum MapType type);
UINT64 MemoryMapPage(const UINT64 physicalAddress, const enum MapType type);
UINT64 MemoryMapGuestVirtual(const UINT64 directoryBase, const UINT64 virtualAddress, const enum MapType mapType);
UINT64 MemoryTranslate(const UINT64 hostVirtual);
UINT64 MemoryTranslateGuestVirtual(const UINT64 directoryBase, const UINT64 guestVirtual, const enum MapType mapType);
UINT64 MemoryTranslateGuestPhysical(UINT64 cr3, UINT64 physicalAddress, enum MapType mapType);
EFI_STATUS MemoryInit(VOID);
EFI_STATUS MemoryCopyGuestVirtual(const UINT64 dirbaseSource, UINT64 virtualSource, const UINT64 dirbaseDestination, UINT64 virtualDestination, UINT64 size);
EFI_STATUS MemoryReadPhysical(UINT64 physicalSource, UINT64 cr3Destination, UINT64 virtualDestination, UINT64 size);