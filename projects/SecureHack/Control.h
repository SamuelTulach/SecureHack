#pragma once

namespace Control
{
    extern "C" UINT64 ExecuteCPUID(...);

    inline bool CheckPresence()
    {
        const auto result = ExecuteCPUID(CPUID_BACKDOOR, COMMAND_CHECK_PRESENCE);
        return result == CPUID_RETURN_VALUE;
    }

    inline bool InitMemory()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        for (DWORD_PTR core = 0; core < sysInfo.dwNumberOfProcessors; ++core)
        {
            const DWORD_PTR affinityMask = 1ULL << core;
            const HANDLE currentThread = GetCurrentThread();
            const DWORD_PTR previousAffinityMask = SetThreadAffinityMask(currentThread, affinityMask);

            if (!previousAffinityMask)
                continue;

            const UINT64 status = ExecuteCPUID(CPUID_BACKDOOR, COMMAND_INIT_MEMORY);
            if (status)
            {
                SetThreadAffinityMask(currentThread, previousAffinityMask);
                return false;
            }

            SetThreadAffinityMask(currentThread, previousAffinityMask);
        }

        return true;
    }

    inline UINT64 GetCR3()
    {
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_GET_CR3);
    }

    inline UINT64 CopyVirtual(const UINT64 sourceCr3, const UINT64 sourceAddress, const UINT64 destinationCr3, const UINT64 destinationAddress, const UINT32 size)
    {
        COMMAND_DATA data;
        data.VirtualMemoryCopy.SourceCr3 = sourceCr3;
        data.VirtualMemoryCopy.SourceAddress = sourceAddress;
        data.VirtualMemoryCopy.DestinationCr3 = destinationCr3;
        data.VirtualMemoryCopy.DestinationAddress = destinationAddress;
        data.VirtualMemoryCopy.Size = size;

        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_VIRTUAL_MEMORY_COPY, &data);
    }

    inline UINT64 ReadPhysical(const UINT64 physicalSource, const UINT64 cr3, const UINT64 virtualDestination, const UINT64 size)
    {
        COMMAND_DATA data;
        data.ReadPhysical.PhysicalSourceAddress = physicalSource;
        data.ReadPhysical.VirtualDestinationAddress = virtualDestination;
        data.ReadPhysical.Cr3 = cr3;
        data.ReadPhysical.Size = size;

        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_READ_PHYSICAL, &data);
    }

    inline SECUREKERNEL_DATA GetSecureKernelInfo()
    {
        COMMAND_DATA data;
        ExecuteCPUID(CPUID_BACKDOOR, COMMAND_SECUREKERNEL_INFO, &data);
        return data.SecureKernelData;
    }

    inline ENCLAVE_DATA GetEnclaveInfo()
    {
        COMMAND_DATA data;
        ExecuteCPUID(CPUID_BACKDOOR, COMMAND_ENCLAVE_INFO, &data);
        return data.EnclaveData;
    }
}