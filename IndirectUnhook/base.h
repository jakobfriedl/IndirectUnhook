/*
 *  ~ base.h ~
 * Common macros and function definitions
 * Author: jakobfriedl
 */

#pragma once
#include <windows.h>
#include <stdio.h>
#include "structs.h"

 // If the following line is set, verbose debug messages are printed to the console windows
#define VERBOSE

/// Macros
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifdef VERBOSE
// The following macros can be used to display debugging information. 
// The messages are only shown if DEBUG mode is enabled.

// Replacing printf
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

// Replacing wprintf
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#define OKAY(MSG, ...) PRINTA("[+] " MSG "\n", ##__VA_ARGS__)
#define OKAY_W(MSG, ...) PRINTW(L"[+] " MSG L"\n", ##__VA_ARGS__)
#define INFO(MSG, ...) PRINTA("[>] " MSG "\n", ##__VA_ARGS__)
#define INFO_W(MSG, ...) PRINTW(L"[>] " MSG L"\n", ##__VA_ARGS__)
#define WARN(MSG, ...) PRINTA("[-] " MSG "\n", ##__VA_ARGS__)
#define WARN_W(MSG, ...) PRINTW(L"[-] " MSG L"\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME)                                        \
    do {                                                                  \
        PRINTA("[X] " FUNCTION_NAME " failed, error: %d. [%s:%d]  \n",    \
                GetLastError(), __FILE__, __LINE__);                      \
    } while (0)
#define PRINT_NTERROR(FUNCTION_NAME)                                      \
    do {                                                                  \
        PRINTA("[X] " FUNCTION_NAME " failed, error: 0x%X. [%s:%d]  \n",  \
                STATUS, __FILE__, __LINE__);                              \
    } while (0)

#endif 

#ifndef VERBOSE
// The following macros will be deleted by the preprocessor, since they include no code. 
// This enables the use of the macros in debug mode, but they will not contain strings that are visible in the binary.

#define PRINTA(MSG, ...)
#define PRINTW(MSG, ...)
#define OKAY(MSG, ...) 
#define OKAY_W(MSG, ...)
#define INFO(MSG, ...)
#define INFO_W(MSG, ...)
#define WARN(MSG, ...) 
#define WARN_W(MSG, ...) 
#define PRINT_ERROR(FUNCTION_NAME)                                        
#define PRINT_NTERROR(FUNCTION_NAME)                                       

#endif 

/// Typedefs
typedef struct _NTDLL_CONFIG {
    PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of ntdll's exported functions   
    PDWORD      pdwArrayOfNames;     // The VA of the array of names of ntdll's exported functions       
    PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of ntdll's exported functions     
    DWORD       dwNumberOfNames;     // The number of exported functions from ntdll.dll                 
    ULONG_PTR   uModule;             // The base address of ntdll - requred to calculated future RVAs  

} NTDLL_CONFIG, *PNTDLL_CONFIG;

typedef struct _NT_SYSCALL {
    DWORD dwSSN;                    // syscall number
    DWORD dwSyscallHash;            // syscall hash value
    PVOID pSyscallAddress;          // syscall address
    PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll    
} NT_SYSCALL, *PNT_SYSCALL;

typedef struct _NTAPI_FUNC {
    NT_SYSCALL NtCreateUserProcess;
    NT_SYSCALL NtReadVirtualMemory;
    NT_SYSCALL NtProtectVirtualMemory;
    NT_SYSCALL NtResumeThread;
    NT_SYSCALL NtTerminateProcess;
    NT_SYSCALL NtClose; 
} NTAPI_FUNC, *PNTAPI_FUNC;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1]; // Number of attributes
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx) (
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);

/// API Hashes
#define NTDLL_crc32h 0x00000000FF02991C
#define NtCreateUserProcess_crc32h 0x0000000037D92BC5
#define RtlCreateProcessParametersEx_crc32h 0x0000000031022D4A
#define NtReadVirtualMemory_crc32h 0x0000000027D761D2
#define NtProtectVirtualMemory_crc32h 0x00000000FC4BBFF4
#define NtResumeThread_crc32h 0x000000002DF4D6E9
#define NtTerminateProcess_crc32h 0x00000000A9B62961
#define NtClose_crc32h 0x00000000A3250A69

/// Global definitions
#define TARGET_PROCESS L"\\??\\C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PARAMS L"C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PATH L"C:\\Windows\\System32"

/// Functions
// External
extern VOID SetSSN(WORD wSystemCall); 
extern RunSyscall();  

#define SET_SYSCALL(NtSys)(SetSSN((DWORD)NtSys.dwSSN,(PVOID)NtSys.pSyscallInstAddress))

// Helpers
unsigned int crc32h(char* message); 
#define HASH(API) crc32h((char*)API)
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwApiNameHash); 
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash); 

VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size); 
PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length); 
BOOL NtCreateSuspendedProcess(IN PNTAPI_FUNC Nt, IN PWSTR szTargetProcess, IN PWSTR szTargetProcessParameters, IN PWSTR szTargetProcessPath, OUT PHANDLE hProcess, OUT PHANDLE hThread); 

// HellsHall 
BOOL InitializeNtSyscalls(PNTAPI_FUNC Nt);

// NTDLL Unhooking
BOOL ReadNtdllFromSuspendedProcess(IN PNTAPI_FUNC Nt, OUT PVOID* ppNtdllBuf); 
BOOL ReplaceNtdllTxtSection(IN PNTAPI_FUNC Nt, IN PVOID pUnhookedNtdll);
VOID CheckHookState(char* cSyscallName, PVOID pSyscallAddress); 
