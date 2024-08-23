#include "base.h"

int wmain(int argc, wchar_t* argv[]) {

    // Calculate hashes
    /*printf("#define %s%s 0x%p\n", "NTDLL", "_crc32h", HASH("ntdll.dll"));
    printf("#define %s%s 0x%p\n", "NtCreateUserProcess", "_crc32h", HASH("NtCreateUserProcess"));
    printf("#define %s%s 0x%p\n", "RtlCreateProcessParametersEx", "_crc32h", HASH("RtlCreateProcessParametersEx"));
    printf("#define %s%s 0x%p\n", "NtReadVirtualMemory", "_crc32h", HASH("NtReadVirtualMemory"));
    printf("#define %s%s 0x%p\n", "NtProtectVirtualMemory", "_crc32h", HASH("NtProtectVirtualMemory"));
    printf("#define %s%s 0x%p\n", "NtResumeThread", "_crc32h", HASH("NtResumeThread"));
    printf("#define %s%s 0x%p\n", "NtTerminateProcess", "_crc32h", HASH("NtTerminateProcess"));
    printf("#define %s%s 0x%p\n", "NtClose", "_crc32h", HASH("NtClose"));
    return EXIT_SUCCESS;*/ 

    // Initialize indirect syscalls
    NTAPI_FUNC Nt = { 0 }; 
    PVOID pNtdll = NULL; 

    INFO("Inject MalDevEdr.dll now and press <Enter> to continue."); 
    getchar();  

    if (!InitializeNtSyscalls(&Nt)) {
        PRINT_ERROR("InitializeNtSyscalls"); 
        return EXIT_FAILURE; 
    }
    OKAY("Indirect syscalls initialized\n"); 

    // Unhook NTDLL by reading clean version from suspended process
    // Set process path in base.h
    if (!ReadNtdllFromSuspendedProcess(&Nt, &pNtdll)) {
        PRINT_ERROR("ReadNtdllFromSuspendedProcess"); 
        return EXIT_FAILURE; 
    }
    OKAY("[ 0x%p ] Clean NTDLL retrieved from suspended process\n", pNtdll); 

    // Checking if a function (NtProtectVirtualMemory) is hooked
    CheckHookState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory")); 

    if (!ReplaceNtdllTxtSection(&Nt, pNtdll)) {
        PRINT_ERROR("ReplaceNtdllTxtSection"); 
        return EXIT_FAILURE; 
    }
    OKAY("NTDLL unhooked"); 

    // Checking hook state again
    CheckHookState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

    return EXIT_SUCCESS; 
}