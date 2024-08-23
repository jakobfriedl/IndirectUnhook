/*
 *  ~ utils.c ~
 * Helper functions
 * Author: jakobfriedl
 */

#include "base.h"

VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

    if ((UsStruct->Buffer = (PWSTR)Buffer)) {

        unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
        if (Length > 0xfffc)
            Length = 0xfffc;

        UsStruct->Length = Length;
        UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
    }

    else UsStruct->Length = UsStruct->MaximumLength = 0;
}

BOOL NtCreateSuspendedProcess(IN PNTAPI_FUNC Nt, IN PWSTR szTargetProcess, IN PWSTR szTargetProcessParameters, IN PWSTR szTargetProcessPath, OUT PHANDLE hProcess, OUT PHANDLE hThread) {

    NTSTATUS STATUS = NULL;

    UNICODE_STRING	UsNtImagePath = { 0 },
        UsCommandLine = { 0 },
        UsCurrentDirectory = { 0 };

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;

    // Allocate attribute list 
    PPS_ATTRIBUTE_LIST pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if (!pAttributeList) {
        PRINT_ERROR("HeapAlloc");
        return FALSE;
    }

    // Initialize PS_CREATE_INFO
    PS_CREATE_INFO CreateInfo = {
        .Size = sizeof(PS_CREATE_INFO),
        .State = PsCreateInitialState
    };

    // Initialize Unicode strings
    _RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
    _RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
    _RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

    // Get function address for RtlCreateProcessParametersEx via API hashing (not a syscall) 
    fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddressH(GetModuleHandleH(NTDLL_crc32h), RtlCreateProcessParametersEx_crc32h);
    if (!RtlCreateProcessParametersEx) {
        PRINT_ERROR("GetProcAddress [RtlCreateProcessParamtersEx]");
        return FALSE;
    }

    // Initialize RTL_USER_PROCESS_PARAMETERS
    STATUS = RtlCreateProcessParametersEx(&ProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("RtlCreateProcessParametersEx");
        goto CLEANUP;
    }

    // Initialize Attribute List
    pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttributeList->Attributes[0].Size = UsNtImagePath.Length;
    pAttributeList->Attributes[0].Value = (ULONG_PTR)UsNtImagePath.Buffer;

    // Create suspended process using NtCreateUserProcess
    SET_SYSCALL(Nt->NtCreateUserProcess);
    STATUS = RunSyscall(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, CREATE_SUSPENDED, NULL, ProcessParameters, &CreateInfo, pAttributeList);
    if (STATUS != STATUS_SUCCESS) {
        PRINT_NTERROR("NtCreateUserProcess");
        goto CLEANUP;
    }

CLEANUP:

    HeapFree(GetProcessHeap(), 0, pAttributeList);

    if (*hProcess == NULL || *hThread == NULL)
        return FALSE;
    else
        return TRUE;

}

// Helper functions replacing APIs
VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size)
{
    PULONG Dest = (PULONG)Destination;
    SIZE_T Count = Size / sizeof(ULONG);

    while (Count > 0)
    {
        *Dest = 0;
        Dest++;
        Count--;
    }

    return;
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}