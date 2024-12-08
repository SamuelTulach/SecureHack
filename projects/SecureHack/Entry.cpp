#include "Global.h"

UINT64 FindEnclaveBase(const UINT64 cr3, const UINT64 enclaveCr3, const UINT64 rip)
{
    UINT64 maximumDepth = rip - 0xF000;
    UINT64 baseAddress = rip & ~0xFFF;
    IMAGE_DOS_HEADER dosHeader = {};
    IMAGE_NT_HEADERS ntHeader = {};

    while (baseAddress > maximumDepth)
    {
        UINT64 status = Control::CopyVirtual(enclaveCr3, baseAddress, cr3, reinterpret_cast<UINT64>(&dosHeader), sizeof(dosHeader));
        if (!status && dosHeader.e_magic == IMAGE_DOS_SIGNATURE)
        {
            const UINT64 ntHeaderAddress = baseAddress + dosHeader.e_lfanew;
            status = Control::CopyVirtual(enclaveCr3, ntHeaderAddress, cr3, reinterpret_cast<UINT64>(&ntHeader), sizeof(ntHeader));
            if (!status && ntHeader.Signature == IMAGE_NT_SIGNATURE)
                return baseAddress;
        }

        baseAddress -= 0x1000;
    }

    return 0;
}

void Entry()
{
    if (!Control::CheckPresence())
    {
        printf("Hyper-V not running or not hooked!\n");
        return;
    }

    if (!Control::InitMemory())
    {
        printf("Failed to init memory!\n");
        return;
    }

    const UINT64 cr3 = Control::GetCR3();
    printf("VM:\n");
    printf(" - CR3: 0x%llX\n", cr3);
    printf("\n");

    const SECUREKERNEL_DATA data = Control::GetSecureKernelInfo();
    printf("securekernel.exe:\n");
    printf(" - Base physical: 0x%llX\n", data.BasePhysical);
    printf(" - Base virtual: 0x%llX\n", data.BaseVirtual);
    printf(" - Size: 0x%llX\n", data.Size);
    printf(" - CR3: 0x%llX\n", data.CR3);

    const UINT64 securekernel = reinterpret_cast<UINT64>(malloc(data.Size));

    /*
     * malloc() itself does not actually populate the paging structures, it
     * only changes VAD. First memory access causes page fault and only
     * after that the page structures are populated.
     */
    memset(reinterpret_cast<PVOID>(securekernel), 0, data.Size);

    UINT64 status = Control::CopyVirtual(data.CR3, data.BaseVirtual, cr3, securekernel, static_cast<UINT32>(data.Size));
    if (status)
    {
        printf("Failed to copy memory!\n");
        return;
    }

    // lea rax, SkpsProcessList
    const ULONG64 localScan = Utils::FindPatternImage(reinterpret_cast<PVOID>(securekernel), "48 8B 2D ? ? ? ? EB");
    if (!localScan)
    {
        printf("Signature scan failed!\n");
        return;
    }

    const UINT64 remoteScan = (localScan - securekernel) + data.BaseVirtual;
    printf(" - SkmiUnmapViewOfSection: 0x%llX\n", remoteScan);

    const UINT64 localSystemProcess = (localScan + 7) + *reinterpret_cast<INT32*>(localScan + 3);
    const UINT64 remoteSystemProcess = *reinterpret_cast<UINT64*>(localSystemProcess);

    printf(" - PsIumSystemProcess: 0x%llX\n", remoteSystemProcess);

    printf("\n");

    SECUREKERNEL_PROCESS systemProcess = {};
    status = Control::CopyVirtual(data.CR3, remoteSystemProcess, cr3, reinterpret_cast<UINT64>(&systemProcess), sizeof(systemProcess));
    if (status)
    {
        printf("Failed to copy memory!\n");
        return;
    }

    printf("System process:\n");
    printf(" - PID: %u\n", systemProcess.ProcessId);
    printf(" - CR3: 0x%llX\n", systemProcess.Cr3);

    printf("\n");

    printf("Waiting for SecureGame.exe process...\n\n");
    DWORD pid;
    do
    {
        pid = Utils::GetPidByName(L"SecureGame.exe");
        Sleep(100);
    } while (!pid);

    Sleep(1000);

    DWORD enclaveSize;
    const UINT64 enclaveModule = Utils::GetMappedFile(pid, L"SecureCore.dll", &enclaveSize);

    printf("Host process:\n");
    printf(" - PID: %u\n", pid);
    printf(" - Enclave: 0x%llX (0x%lX)\n", enclaveModule, enclaveSize);

    printf("\n");

    const ENCLAVE_DATA enclave = Control::GetEnclaveInfo();

    printf("Enclave:\n");
    printf(" - Total calls: %llu\n", enclave.TotalCalls);
    printf(" - Last RIP: 0x%llX\n", enclave.LastRip);
    printf(" - Last CR3: 0x%llX\n", enclave.LastCR3);

    const UINT64 moduleBase = FindEnclaveBase(cr3, enclave.LastCR3, enclave.LastRip);
    if (!moduleBase)
    {
        printf("Failed to find module base!\n");
        return;
    }

    printf(" - Headers: 0x%llX\n", moduleBase);

    IMAGE_DOS_HEADER dosHeader = {};
    IMAGE_NT_HEADERS ntHeader = {};
    Control::CopyVirtual(enclave.LastCR3, moduleBase, cr3, reinterpret_cast<UINT64>(&dosHeader), sizeof(dosHeader));
    Control::CopyVirtual(enclave.LastCR3, moduleBase + dosHeader.e_lfanew, cr3, reinterpret_cast<UINT64>(&ntHeader), sizeof(ntHeader));

    printf(" - Image base: 0x%llX\n", ntHeader.OptionalHeader.ImageBase);
    printf(" - Checksum: 0x%X\n", ntHeader.OptionalHeader.CheckSum);
    printf(" - Size of image: 0x%X\n", ntHeader.OptionalHeader.SizeOfImage);
    printf(" - Timestamp: 0x%X\n", ntHeader.FileHeader.TimeDateStamp);

    printf("\n");

    /*printf("Game:\n");
    while (true)
    {
        constexpr UINT64 leftScoreOffset = 0x67ac;
        constexpr UINT64 rightScoreOffset = 0x67bc;

        int leftScore = 0;
        Control::CopyVirtual(enclave.LastCR3, moduleBase + leftScoreOffset, cr3, reinterpret_cast<UINT64>(&leftScore), sizeof(leftScore));

        int rightScore = 0;
        Control::CopyVirtual(enclave.LastCR3, moduleBase + rightScoreOffset, cr3, reinterpret_cast<UINT64>(&rightScore), sizeof(rightScore));

        printf("\r - Left score: %i Right score: %i", leftScore, rightScore);

        Sleep(100);
    }*/

    while (true)
    {
        printf("Press key to overwrite score...\n");
        getchar();

        constexpr UINT64 leftScoreOffset = 0x67ac;
        constexpr UINT64 rightScoreOffset = 0x67bc;

        int leftScore = 999999;
        Control::CopyVirtual(cr3, reinterpret_cast<UINT64>(&leftScore), enclave.LastCR3, moduleBase + leftScoreOffset, sizeof(leftScore));

        int rightScore = 0;
        Control::CopyVirtual(cr3, reinterpret_cast<UINT64>(&rightScore), enclave.LastCR3, moduleBase + rightScoreOffset, sizeof(rightScore));
    }

    printf("\n");
}

int main()
{
    Entry();
    getchar();
    return 0;
}