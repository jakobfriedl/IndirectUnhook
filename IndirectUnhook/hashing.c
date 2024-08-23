/*
 *  ~ hashing.c ~
 * API Hashing
 * Author: jakobfriedl
 */

#include "base.h"

#define SEED 0xAD1F86BE

unsigned int crc32h(char* message) {
    int i, crc;
    unsigned int byte, c;
    const unsigned int g0 = SEED, g1 = g0 >> 1,
        g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
        g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

    i = 0;
    crc = 0xFFFFFFFF;
    while ((byte = message[i]) != 0) {    // Get next byte.
        crc = crc ^ byte;
        c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
            ((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
            ((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
            ((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
        crc = ((unsigned)crc >> 8) ^ c;
        i = i + 1;
    }
    return ~crc;
}

/// Custom GetProcAddress 
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwApiNameHash) {

    if (!hModule || !dwApiNameHash) return NULL;

    PBYTE pBase = (PBYTE)hModule;

    // Get DOS Header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    // Get NT Headers
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    // Get Optional Header
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
    if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        return NULL;
    }

    // Get pointer to the Export Table structure
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get relevant information from the export directory to search for a specific function
    PDWORD FnNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);			// function names
    PDWORD FnAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);  // function addresses
    PWORD FnOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals); // function ordinals

    // Loop over exported functions 
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

        // Get name of the function 
        CHAR* pFnName = (CHAR*)(pBase + FnNameArray[i]); // Name
        WORD wFnOrdinal = FnOrdinalArray[i]; // Ordinal
        PVOID pFnAddress = (PVOID)(pBase + FnAddressArray[wFnOrdinal]); // Address

        // Search for the function that matches the hash and return it
        if (HASH(pFnName) == dwApiNameHash) {
#ifdef _DEBUG
            OKAY("[ 0x%p ] Found function \"%s\"", pFnAddress, pFnName);
#endif
            return pFnAddress;
        }
    }

    WARN("Function for hash 0x%X not found.", dwApiNameHash);
    return NULL;
}

/// Custom GetModuleHandle
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash) {

    if (!dwModuleNameHash) return NULL;

    PPEB pPeb = NULL;

    // Use to __readgsqword macro to get the address of the PPEB by specifying the offset of 0x60 (0x30 on 32-bit systems, since PVOID has a since of 4 on there.
#ifdef _WIN64
    pPeb = __readgsqword(0x60); // sizeof(PVOID) = 8 --[ * 12 ]--> 96 --[ HEX ]--> 0x60
#elif _WIN32
    pPeb = __readgsqword(0x30); // sizeof(PVOID) = 4 --> [ * 12 ] = 48 --[ HEX ]-- 0x30
#endif 

    // Get PED_LDR_DATA structure
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);

    // Get first element of the linked list which contains information about the first module
    // Doubly-linked lists use the Flink and Blink elements as the head and tail pointers, respectively. 
    // This means Flink points to the next node in the list whereas the Blink element points to the previous node in the list. 
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Loop over all modules
    while (pDte) {

        if (pDte->FullDllName.Length == NULL || pDte->FullDllName.Length > MAX_PATH) {
            break;
        }

        // Convert FullDllName.Buffer to lowercase string
        CHAR szLowercaseDllName[MAX_PATH];

        DWORD i = 0;
        for (i = 0; i < pDte->FullDllName.Length; i++) {
            szLowercaseDllName[i] = (CHAR)tolower(pDte->FullDllName.Buffer[i]);
        }
        szLowercaseDllName[i] = '\0';

        // Check if hashes match
        if (HASH(szLowercaseDllName) == dwModuleNameHash) {
            // The DLL base address is InInitializationOrderLinks.Flink, or Reserved2[0]
            // If the undocumented structs are not present, the next line could also be written as the following
            // return (HMODULE)(pDte->Reserved2[0]
            HANDLE hModule = (HMODULE)pDte->InInitializationOrderLinks.Flink;

#ifdef _DEBUG
            OKAY_W(L"[ 0x%p ] Found module \"%s\"", hModule, pDte->FullDllName.Buffer);
#endif

            return hModule;
        }

        // Move to the next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}