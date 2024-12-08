#include "Global.h"

/*
 * SectionAlignment (/ALIGN) has to be set to 4096
 */
#pragma section(".pdpt", read, write)
__declspec(allocate(".pdpt")) PDPTE_64 Pdpt[512];
#pragma section(".pd", read, write)
__declspec(allocate(".pd")) PDE_64 Pd[512];
#pragma section(".pt", read, write)
__declspec(allocate(".pt")) PTE_64 Pt[512];

PML4E_64* HyperVPml4 = (PML4E_64*)SELF_REF_PML4;

UINT64 PdptPhysical = 0;
UINT64 PdPhysical = 0;
UINT64 PtPhysical = 0;

UINT32 MemoryGetCoreIndex(VOID)
{
    CPUID_EAX_01 cpuidResult;
    __cpuid((INT32*)&cpuidResult, 1);
    return cpuidResult.CpuidAdditionalInformation.InitialApicId;
}

UINT64 MemoryGetMapVirtual(UINT16 offset, enum MapType type)
{
    CPUID_EAX_01 cpuidResult;
    __cpuid((INT32*)&cpuidResult, 1);

    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = MAPPING_ADDRESS_BASE;
    virtualAddress.PtIndex = MemoryGetCoreIndex() * 2 + (UINT32)type;
    return virtualAddress.Value + offset;
}

UINT64 MemoryMapPage(const UINT64 physicalAddress, const enum MapType type)
{
    CPUID_EAX_01 cpuidResult;
    __cpuid((INT32*)&cpuidResult, 1);

    const UINT32 index = MemoryGetCoreIndex() * 2 + (UINT32)type;
    Pt[index].PageFrameNumber = physicalAddress >> 12;

    const UINT64 mappedAddress = MemoryGetMapVirtual(physicalAddress & PAGE_MASK, type);

    __invlpg((void*)mappedAddress);

    return mappedAddress;
}

UINT64 MemoryMapGuestVirtual(const UINT64 directoryBase, const UINT64 virtualAddress, const enum MapType mapType)
{
    const UINT64 guestPhysical = MemoryTranslateGuestVirtual(directoryBase, virtualAddress, mapType);
    if (!guestPhysical)
        return 0;

    return MemoryMapPage(guestPhysical, mapType);
}

UINT64 MemoryTranslate(const UINT64 hostVirtual)
{
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = hostVirtual;

    VIRTUAL_ADDRESS cursor;
    cursor.Value = (UINT64)HyperVPml4;

    if (!((PML4E_64*)cursor.Pointer)[virtualAddress.Pml4Index].Present)
        return 0;

    cursor.PtIndex = virtualAddress.Pml4Index;
    if (!((PDPTE_64*)cursor.Pointer)[virtualAddress.PdptIndex].Present)
        return 0;

    // 1GB large page
    if (((PDPTE_64*)cursor.Pointer)[virtualAddress.PdptIndex].LargePage)
        return (((PDPTE_64*)cursor.Pointer)[virtualAddress.PdptIndex].PageFrameNumber << 30) + virtualAddress.Offset;

    cursor.PdIndex = virtualAddress.Pml4Index;
    cursor.PtIndex = virtualAddress.PdptIndex;
    if (!((PDE_64*)cursor.Pointer)[virtualAddress.PdIndex].Present)
        return 0;

    // 2MB large page
    if (((PDE_64*)cursor.Pointer)[virtualAddress.PdIndex].LargePage)
        return (((PDE_64*)cursor.Pointer)[virtualAddress.PdIndex].PageFrameNumber << 21) + virtualAddress.Offset;

    cursor.PdptIndex = virtualAddress.Pml4Index;
    cursor.PdIndex = virtualAddress.PdptIndex;
    cursor.PtIndex = virtualAddress.PdIndex;
    if (!((PTE_64*)cursor.Pointer)[virtualAddress.PtIndex].Present)
        return 0;

    return (((PTE_64*)cursor.Pointer)[virtualAddress.PtIndex].PageFrameNumber << 12) + virtualAddress.Offset;
}

UINT64 MemoryTranslateGuestVirtual(const UINT64 directoryBase, const UINT64 guestVirtual, const enum MapType mapType)
{
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = guestVirtual;

    PML4E_64* pml4 = (PML4E_64*)MemoryMapPage(directoryBase, mapType);
    if (!pml4 || !pml4[virtualAddress.Pml4Index].Present)
        return 0;

    PDPTE_64* pdpt = (PDPTE_64*)MemoryMapPage(pml4[virtualAddress.Pml4Index].PageFrameNumber << 12, mapType);
    if (!pdpt || !pdpt[virtualAddress.PdptIndex].Present)
        return 0;

    // 1GB large page
    if (pdpt[virtualAddress.PdptIndex].LargePage)
        return (pdpt[virtualAddress.PdptIndex].PageFrameNumber << 12) + virtualAddress.Offset;

    PDE_64* pd = (PDE_64*)MemoryMapPage(pdpt[virtualAddress.PdptIndex].PageFrameNumber << 12, mapType);
    if (!pd || !pd[virtualAddress.PdIndex].Present)
        return 0;

    // 2MB large page
    if (pd[virtualAddress.PdIndex].LargePage)
        return (pd[virtualAddress.PdIndex].PageFrameNumber << 12) + virtualAddress.Offset;

    PTE_64* pt = (PTE_64*)MemoryMapPage(pd[virtualAddress.PdIndex].PageFrameNumber << 12, mapType);
    if (!pt || !pt[virtualAddress.PtIndex].Present)
        return 0;

    return (pt[virtualAddress.PtIndex].PageFrameNumber << 12) + virtualAddress.Offset;
}

UINT64 MemoryTranslateGuestPhysical(const UINT64 cr3, const UINT64 physicalAddress, const enum MapType mapType)
{
    VIRTUAL_ADDRESS guestPhys;
    guestPhys.Value = physicalAddress;

    const PML4E_64* pml4 = (PML4E_64*)MemoryMapPage(cr3, mapType);

    if (!pml4[guestPhys.Pml4Index].Present)
        return 0;

    const PDPTE_64* pdpt = (PDPTE_64*)MemoryMapPage(pml4[guestPhys.Pml4Index].PageFrameNumber << 12, mapType);
    if (!pdpt[guestPhys.PdptIndex].Present)
        return 0;

    PDE_64* pd = (PDE_64*)MemoryMapPage(pdpt[guestPhys.PdptIndex].PageFrameNumber << 12, mapType);
    if (!pd[guestPhys.PdIndex].Present)
        return 0;

    if (((PDE_64*)pd)[guestPhys.PdIndex].LargePage)
        return (((PDE_64*)pd)[guestPhys.PdIndex].PageFrameNumber << 21) + guestPhys.Offset;

    const PTE_64* pt = (PTE_64*)MemoryMapPage(pd[guestPhys.PdIndex].PageFrameNumber << 12, mapType);
    if (!pt[guestPhys.PtIndex].Present)
        return 0;

    return (pt[guestPhys.PtIndex].PageFrameNumber << 12) + guestPhys.Offset;
}

EFI_STATUS MemoryInit(VOID)
{
    DebugFormat("Initialization on core %d:\n", MemoryGetCoreIndex());

    PdptPhysical = MemoryTranslate((UINT64)Pdpt);
    DebugFormat(" - PDPT: 0x%p\n", PdptPhysical);
    PdPhysical = MemoryTranslate((UINT64)Pd);
    DebugFormat(" - PD: 0x%p\n", PdPhysical);
    PtPhysical = MemoryTranslate((UINT64)Pt);
    DebugFormat(" - PT: 0x%p\n", PtPhysical);

    if (!PdptPhysical || !PdPhysical || !PtPhysical)
        return EFI_INVALID_PARAMETER;

    HyperVPml4[MAPPING_PML4_IDX].Present = 1;
    HyperVPml4[MAPPING_PML4_IDX].PageFrameNumber = PdptPhysical >> 12;
    HyperVPml4[MAPPING_PML4_IDX].Supervisor = 0;
    HyperVPml4[MAPPING_PML4_IDX].Write = 1;

    Pdpt[511].Present = 1;
    Pdpt[511].PageFrameNumber = PdPhysical >> 12;
    Pdpt[511].Supervisor = 0;
    Pdpt[511].Write = 1;

    Pd[511].Present = 1;
    Pd[511].PageFrameNumber = PtPhysical >> 12;
    Pd[511].Supervisor = 0;
    Pd[511].Write = 1;

    for (UINT32 idx = 0; idx < 512; idx++)
    {
        Pt[idx].Present = 1;
        Pt[idx].Supervisor = 0;
        Pt[idx].Write = 1;
    }

    __wbinvd();

    PML4E_64* mappedPml4 = (PML4E_64*)MemoryMapPage(__readcr3(), MapSource);
    const UINT64 translated = MemoryTranslate((UINT64)mappedPml4);
    if (translated != __readcr3())
        return EFI_NO_MAPPING;

    if (mappedPml4[SELF_REF_PML4_IDX].PageFrameNumber != (__readcr3() >> 12))
        return EFI_VOLUME_CORRUPTED;

    if (mappedPml4[MAPPING_PML4_IDX].PageFrameNumber != (PdptPhysical >> 12))
        return EFI_VOLUME_CORRUPTED;

    DebugFormat(" - CR3: 0x%p 0x%p 0x%p\n", __readcr3(), mappedPml4, translated);
    return EFI_SUCCESS;
}

EFI_STATUS MemoryCopyGuestVirtual(const UINT64 dirbaseSource, UINT64 virtualSource, const UINT64 dirbaseDestination, UINT64 virtualDestination, UINT64 size)
{
    while (size)
    {
        UINT64 destSize = PAGE_SIZE - (virtualDestination & PAGE_MASK);
        if (size < destSize)
            destSize = size;

        UINT64 srcSize = PAGE_SIZE - (virtualSource & PAGE_MASK);
        if (size < srcSize)
            srcSize = size;

        VOID* mappedSrc = (VOID*)MemoryMapGuestVirtual(dirbaseSource, virtualSource, MapSource);
        if (!mappedSrc)
            return EFI_INVALID_PARAMETER;

        VOID* mappedDest = (VOID*)MemoryMapGuestVirtual(dirbaseDestination, virtualDestination, MapDestination);
        if (!mappedDest)
            return EFI_INVALID_PARAMETER;

        const UINT64 currentSize = (destSize < srcSize) ? destSize : srcSize;
        /*
         * Do NOT use CopyMem, since it internally uses gBS->CopyMem
         */
        InternalCopyMemory(mappedDest, mappedSrc, currentSize);

        virtualSource += currentSize;
        virtualDestination += currentSize;
        size -= currentSize;
    }

    return EFI_SUCCESS;
}

EFI_STATUS MemoryReadPhysical(UINT64 physicalSource, UINT64 cr3Destination, UINT64 virtualDestination, UINT64 size)
{
    while (size)
    {
        UINT64 destSize = PAGE_SIZE - (virtualDestination & PAGE_MASK);
        if (size < destSize)
            destSize = size;

        UINT64 srcSize = PAGE_SIZE - (physicalSource & PAGE_MASK);
        if (size < srcSize)
            srcSize = size;

        VOID* mappedSrc = (VOID*)MemoryMapPage(physicalSource, MapSource);
        if (!mappedSrc)
            return EFI_INVALID_PARAMETER;

        VOID* mappedDest = (VOID*)MemoryMapGuestVirtual(cr3Destination, virtualDestination, MapDestination);
        if (!mappedDest)
            return EFI_INVALID_PARAMETER;

        const UINT64 currentSize = (destSize < srcSize) ? destSize : srcSize;
        InternalCopyMemory(mappedDest, mappedSrc, currentSize);

        physicalSource += currentSize;
        virtualDestination += currentSize;
        size -= currentSize;
    }

    return EFI_SUCCESS;
}
