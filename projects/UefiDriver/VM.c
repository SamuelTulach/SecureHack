#include "Global.h"

BOOLEAN CalledVmExit = FALSE;
BOOLEAN CalledVtlReturn = FALSE;

INT32 OriginalOffsetFromHook = 0x0;
SECUREKERNEL_INFO SecureKernelInfo;
ENCLAVE_INFO EnclaveInfo = { 0 };

PVMCB_CONTROL_AREA GetVmcb(const UINT64 context)
{
    const UINT64 v3 = *((UINT64*)context - 384);
    const UINT64** v7 = (UINT64**)(v3 + 5056);
    return (PVMCB_CONTROL_AREA)(**v7);
}

COMMAND_DATA GetCommand(const PVMCB_CONTROL_AREA vmcb, const PGUEST_CONTEXT context)
{
    CR3 cr3;
    cr3.AsUInt = vmcb->Cr3;

    const UINT64 directoryBase = cr3.AddressOfPageDirectory << 12;
    const UINT64 commandPage = MemoryMapGuestVirtual(directoryBase, context->R8, MapSource);

    return *(COMMAND_DATA*)commandPage;
}

VOID SetCommand(const PVMCB_CONTROL_AREA vmcb, const PGUEST_CONTEXT context, COMMAND_DATA* data)
{
    CR3 cr3;
    cr3.AsUInt = vmcb->Cr3;

    const UINT64 directoryBase = cr3.AddressOfPageDirectory << 12;
    const UINT64 commandPage = MemoryMapGuestVirtual(directoryBase, context->R8, MapSource);

    *(COMMAND_DATA*)commandPage = *data;
}

VOID HandleCPUID(const PVMCB_CONTROL_AREA vmcb, const PGUEST_CONTEXT context)
{
    COMMAND_DATA data;
    switch (context->Rdx)
    {
    case COMMAND_CHECK_PRESENCE:
        vmcb->Rax = CPUID_RETURN_VALUE;
        break;
    case COMMAND_INIT_MEMORY:
        vmcb->Rax = MemoryInit();
        break;
    case COMMAND_GET_CR3:
        vmcb->Rax = vmcb->Cr3;
        break;
    case COMMAND_VIRTUAL_MEMORY_COPY:
        data = GetCommand(vmcb, context);
        vmcb->Rax = MemoryCopyGuestVirtual(data.VirtualMemoryCopy.SourceCr3, data.VirtualMemoryCopy.SourceAddress, data.VirtualMemoryCopy.DestinationCr3, data.VirtualMemoryCopy.DestinationAddress, data.VirtualMemoryCopy.Size);
        break;
    case COMMAND_READ_PHYSICAL:
        data = GetCommand(vmcb, context);
        vmcb->Rax = MemoryReadPhysical(data.ReadPhysical.PhysicalSourceAddress, data.ReadPhysical.Cr3, data.ReadPhysical.VirtualDestinationAddress, data.ReadPhysical.Size);
        break;
    case COMMAND_SECUREKERNEL_INFO:
        data.SecureKernelData.BaseVirtual = SecureKernelInfo.BaseAddressVirtual;
        data.SecureKernelData.BasePhysical = SecureKernelInfo.BaseAddressPhysical;
        data.SecureKernelData.Size = SecureKernelInfo.Size;
        data.SecureKernelData.CR3 = SecureKernelInfo.CR3;
        SetCommand(vmcb, context, &data);
        break;
    case COMMAND_ENCLAVE_INFO:
        data.EnclaveData.TotalCalls = EnclaveInfo.TotalCalls;
        data.EnclaveData.LastRip = EnclaveInfo.LastRip;
        data.EnclaveData.LastCR3 = EnclaveInfo.LastCR3;
        SetCommand(vmcb, context, &data);
        break;
    default:
        break;
    }
}

VOID HandleVTL1ToVTL0(const PVMCB_CONTROL_AREA vmcb, PGUEST_CONTEXT context)
{
    const UINT64 rspPhysical = MemoryTranslateGuestVirtual(vmcb->Cr3, vmcb->Rsp, MapSource);
    const UINT64 rspMapped = MemoryMapPage(rspPhysical, MapSource);

    const UINT64 returnAddress = *(UINT64*)rspMapped;
    const UINT64 returnPhysical = MemoryTranslateGuestVirtual(vmcb->Cr3, returnAddress, MapSource);

    DebugFormat("VTL1 to VTL0 transition:\n");
    DebugFormat(" - RIP: 0x%p\n", vmcb->Rip);
    DebugFormat(" - RSP: 0x%p\n", vmcb->Rsp);
    DebugFormat(" - CR3: 0x%p\n", vmcb->Cr3);
    DebugFormat(" - Stack physical: 0x%p\n", rspPhysical);
    DebugFormat(" - Stack mapped: 0x%p\n", rspMapped);
    DebugFormat(" - Return virtual: 0x%p\n", returnAddress);
    DebugFormat(" - Return physical: 0x%p\n", returnPhysical);

    UINT64 currentPagePhysical = returnPhysical & ~0xFFF;
    const UINT64 searchLimit = 1024 * 1024 * 64; // 64mb
    UINT64 searchCount = 0;

    while (searchCount < searchLimit)
    {
        const UINT64 currentPageMapped = MemoryMapPage(currentPagePhysical, MapSource);
        const PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)currentPageMapped;
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            if (dosHeader->e_lfanew > 0 && dosHeader->e_lfanew < 4096 - sizeof(IMAGE_NT_HEADERS))
            {
                const PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT64)dosHeader + dosHeader->e_lfanew);
                if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
                {
                    DebugFormat("Found securekernel.exe:\n");
                    DebugFormat(" - Base virtual: 0x%p\n", ntHeaders->OptionalHeader.ImageBase);
                    DebugFormat(" - Base physical: 0x%p\n", currentPagePhysical);
                    DebugFormat(" - Checksum: 0x%x\n", ntHeaders->OptionalHeader.CheckSum);
                    DebugFormat(" - Size of image: 0x%x\n", ntHeaders->OptionalHeader.SizeOfImage);

                    SecureKernelInfo.BaseAddressVirtual = ntHeaders->OptionalHeader.ImageBase;
                    SecureKernelInfo.BaseAddressPhysical = currentPagePhysical;
                    SecureKernelInfo.Size = ntHeaders->OptionalHeader.SizeOfImage;
                    SecureKernelInfo.CR3 = vmcb->Cr3;
                    break;
                }
            }
        }

        currentPagePhysical -= 4096;
        searchCount += 4096;
    }

    if (searchCount >= searchLimit)
    {
        DebugFormat("No image was found\n");
        return;
    }
}

UINT64 HookedVmExitHandler(VOID* arg1, VOID* arg2, const PGUEST_CONTEXT context)
{
    if (!CalledVmExit)
    {
        CalledVmExit = TRUE;

        /*
         * Debug logging into serial will stop working after the OS boots up.
         * Just a heads-up so you don't spend 2 hours trying to figure out
         * why is the vm exit not being triggered to realize the logging is
         * simply not doing anything and the vm exit is being triggered.
         * In this stage, it should still work though.
         */
        DebugFormat("VM exit handler called from 0x%p\n", _ReturnAddress());

        MemoryInit();
    }

    PVMCB_CONTROL_AREA vmcb = GetVmcb((UINT64)arg2);
    if (vmcb->ExitCode == VMEXIT_CPUID && context->Rcx == CPUID_BACKDOOR)
    {
        HandleCPUID(vmcb, context);

        vmcb->Rip = vmcb->NRip;
        return __readgsqword(0);
    }

    if (!CalledVtlReturn && vmcb->ExitCode == VMEXIT_VMMCALL && context->Rcx == HvCallVtlReturn)
    {
        CalledVtlReturn = TRUE;
        HandleVTL1ToVTL0(vmcb, context);
    }

    if (vmcb->ExitCode == VMEXIT_CPUID && 
        vmcb->Rip < 0x7FFFFFFFFFFF &&
        vmcb->LStar > SecureKernelInfo.BaseAddressVirtual &&
        vmcb->LStar < SecureKernelInfo.BaseAddressVirtual + SecureKernelInfo.Size)
    {
        EnclaveInfo.TotalCalls++;
        EnclaveInfo.LastRip = vmcb->Rip;
        EnclaveInfo.LastCR3 = vmcb->Cr3;
    }

    return ((OriginalVmExitHandler_t)((UINT64)HookedVmExitHandler + OriginalOffsetFromHook))(arg1, arg2, context);
}