#include <cstdio>
#include <Windows.h>
#include <winternl.h>




#define HASH_LoadLibraryA 0x0726774C
#define HASH_LdrGetProcedureAddress 0x5ed941b5
#define HASH_NtAllocateVirtualMemory 0x9488b12d
#define HASH_LdrLoadDll 0xbdbf9c13
#define HASH_RtlInitAnsiString 0x8085fd68
#define HASH_RtlAnsiStringToUnicodeString 0x5ae972b3
#define HASH_RtlFreeUnicodeString 0x3fef5ce5


#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOL Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
typedef int (WINAPI* pfnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef NTSTATUS(WINAPI* pfnLdrGetProcedureAddress)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
typedef VOID(WINAPI* pfnRtlFreeUnicodeString)(_Inout_ PUNICODE_STRING UnicodeString);
typedef  VOID(WINAPI* pfnRtlInitAnsiString)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ         SourceString);
typedef NTSTATUS(WINAPI* pfnRtlAnsiStringToUnicodeString)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* pfnLdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY* pfnProcDllMain)(LPVOID, DWORD, LPVOID);
typedef NTSTATUS(WINAPI* pfnNtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

typedef struct _FUNCTIONS
{
    pfnLoadLibraryA fnLoadLibraryA;
    pfnLdrGetProcedureAddress  fnLdrGetProcedureAddress;
    pfnNtAllocateVirtualMemory  fnNtAllocateVirtualMemory;
    pfnLdrLoadDll  fnLdrLoadDll;
    pfnRtlInitAnsiString  fnRtlInitAnsiString;
    pfnRtlAnsiStringToUnicodeString  fnRtlAnsiStringToUnicodeString;
    pfnRtlFreeUnicodeString  fnRtlFreeUnicodeString;


}Functions, * Pfunctions;


void Initfunctions(Pfunctions pfn);
HMODULE GetProcAddressWithHash(DWORD dwModuleFunctionHash);


uintptr_t __fastcall ShellCodeEntry(HMODULE hModule)
{
    Functions fn;
   
    Initfunctions(&fn);




    LPCVOID lpFileData = hModule;




    pfnProcDllMain pDllMain = NULL;
    void* pMemoryAddress = NULL;



    ANSI_STRING ansiStr;
    UNICODE_STRING UnicodeString;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;
    int ImageSize = 0;

    int nAlign = 0;
    int i = 0;


    pDosHeader = (PIMAGE_DOS_HEADER)lpFileData; 

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
    
        return  0;
    }

 
    pNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpFileData + pDosHeader->e_lfanew); 
    uintptr_t DataLength = pNTHeader->OptionalHeader.SizeOfImage;
    if ((uintptr_t)DataLength < (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
    {
        return  0;
    }

    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) 
    {
        return  0;
    }
    if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
    {
        return 0;
    }
    if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) 
    {
        return 0;
    }
    if (pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
    {
        return 0;
    }



    pSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)pNTHeader + sizeof(IMAGE_NT_HEADERS));
   
    for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
    {
        if ((pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > (uintptr_t)DataLength)
        {
            return 0;
        }
    }


    nAlign = pNTHeader->OptionalHeader.SectionAlignment; 

   
    ImageSize = (pNTHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;

    for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
    {
      
        int CodeSize = pSectionHeader[i].Misc.VirtualSize;
        int LoadSize = pSectionHeader[i].SizeOfRawData;
        int MaxSize = (LoadSize > CodeSize) ? (LoadSize) : (CodeSize);

        int SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;
        if (ImageSize < SectionSize)
            ImageSize = SectionSize; //Use the Max;
    }
    if (ImageSize == 0)
    {
        return 0;
    }


    SIZE_T uSize = ImageSize;
    fn.fnNtAllocateVirtualMemory((HANDLE)-1, &pMemoryAddress, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);



    if (pMemoryAddress != NULL)
    {

   
        int HeaderSize = pNTHeader->OptionalHeader.SizeOfHeaders;
        int SectionSize = pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        int MoveSize = HeaderSize + SectionSize;
        //???????????
        for (i = 0; i < MoveSize; i++)
        {
            *((PCHAR)pMemoryAddress + i) = *((PCHAR)lpFileData + i);
        }
        //memmove(pMemoryAddress, lpFileData, MoveSize);//

        for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
        {
            if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)continue;
    
            void* pSectionAddress = (void*)((uintptr_t)pMemoryAddress + pSectionHeader[i].VirtualAddress);
           
        //	memmove((void *)pSectionAddress,(void *)((uintptr_t)lpFileData + pSectionHeader[i].PointerToRawData),	pSectionHeader[i].SizeOfRawData);
         
            for (size_t k = 0; k < pSectionHeader[i].SizeOfRawData; k++)
            {
                *((PCHAR)pSectionAddress + k) = *((PCHAR)lpFileData + pSectionHeader[i].PointerToRawData + k);
            }
        }
    

        if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
            && pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
        {

            uintptr_t Delta = (uintptr_t)pMemoryAddress - pNTHeader->OptionalHeader.ImageBase;
            uintptr_t* pAddress;
         
            PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((uintptr_t)pMemoryAddress
                + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //?????????¦Ë??
            {
                WORD* pLocData = (WORD*)((uintptr_t)pLoc + sizeof(IMAGE_BASE_RELOCATION));
              
                int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (i = 0; i < NumberOfReloc; i++)
                {
                    if ((uintptr_t)(pLocData[i] & 0xF000) == 0x00003000 || (uintptr_t)(pLocData[i] & 0xF000) == 0x0000A000) //??????????????????
                    {
                  
                        pAddress = (uintptr_t*)((uintptr_t)pMemoryAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                        *pAddress += Delta;
                    }
                }
           
                pLoc = (PIMAGE_BASE_RELOCATION)((uintptr_t)pLoc + pLoc->SizeOfBlock);
            }
            /***********************************************************************/
        }


        uintptr_t Offset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (Offset == 0)
        {
            //No Import Table
            return  0;
        }

        PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)pMemoryAddress + Offset);

        PIMAGE_IMPORT_BY_NAME pByName = NULL;
        while (pID->Characteristics != 0)
        {
            PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((uintptr_t)pMemoryAddress + pID->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((uintptr_t)pMemoryAddress + pID->OriginalFirstThunk);
            //???dll??????
            char* pName = (char*)((uintptr_t)pMemoryAddress + pID->Name);
            HANDLE hDll = 0;

            fn.fnRtlInitAnsiString(&ansiStr, pName);
            fn.fnRtlAnsiStringToUnicodeString(&UnicodeString, &ansiStr, true);
            fn.fnLdrLoadDll(NULL, NULL, &UnicodeString, &hDll);
            fn.fnRtlFreeUnicodeString(&UnicodeString);

            if (hDll == NULL) {

                return  0;
            }

            for (i = 0; ; i++)
            {
                if (pOriginalIAT[i].u1.Function == 0)break;
                FARPROC lpFunction = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) 
                {
                    if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal))
                    {

                        fn.fnLdrGetProcedureAddress(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
                    }
                }
                else
                {
                  
                    pByName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)pMemoryAddress + (uintptr_t)(pOriginalIAT[i].u1.AddressOfData));
                    if ((char*)pByName->Name)
                    {
                        fn.fnRtlInitAnsiString(&ansiStr, (char*)pByName->Name);
                        fn.fnLdrGetProcedureAddress(hDll, &ansiStr, 0, &lpFunction);

                    }

                }

     

                if (lpFunction != NULL) //??????
                    pRealIAT[i].u1.Function = (uintptr_t)lpFunction;
                else
                    return 0;
            }

            //move to next
            pID = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
        }

      
        pNTHeader->OptionalHeader.ImageBase = (uintptr_t)pMemoryAddress;

        //NtProtectVirtualMemory((HANDLE)-1, &pMemoryAddress, (PSIZE_T)&ImageSize, PAGE_EXECUTE_READ, &oldProtect);
        pDllMain = (pfnProcDllMain)(pNTHeader->OptionalHeader.AddressOfEntryPoint + (uintptr_t)pMemoryAddress);

        pDllMain((HMODULE)pMemoryAddress, DLL_PROCESS_ATTACH, pMemoryAddress);

    }


    return (uintptr_t)pMemoryAddress;

}



HMODULE GetProcAddressWithHash(DWORD dwModuleFunctionHash)
{
    PPEB PebAddress;
    PMY_PEB_LDR_DATA pLdr;
    PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
    PVOID pModuleBase;
    PIMAGE_NT_HEADERS pNTHeader;
    DWORD dwExportDirRVA;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    PLIST_ENTRY pNextModule;
    DWORD dwNumFunctions;
    USHORT usOrdinalTableIndex;
    PDWORD pdwFunctionNameBase;
    PCSTR pFunctionName;
    UNICODE_STRING BaseDllName;
    DWORD dwModuleHash;
    DWORD dwFunctionHash;
    PCSTR pTempChar;
    DWORD i;

#if defined(_WIN64)
    PebAddress = (PPEB)__readgsqword(0x60);
#elif defined(_M_ARM)
    PebAddress = (PPEB)((ULONG_PTR)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0);
    __emit(0x00006B1B);
#else
    PebAddress = (PPEB)__readfsdword(0x30);
#endif

    pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
    pNextModule = pLdr->InLoadOrderModuleList.Flink;
    pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

    while (pDataTableEntry->DllBase != NULL)
    {
        dwModuleHash = 0;
        pModuleBase = pDataTableEntry->DllBase;
        BaseDllName = pDataTableEntry->BaseDllName;
        pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
        dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

        //?????????????
        pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

        // ????????öö?????¦Ê¦Ê?????????????????? ??????????
        if (dwExportDirRVA == 0)
        {
            continue;
        }

        //??????????
        for (i = 0; i < BaseDllName.MaximumLength; i++)
        {
            pTempChar = ((PCSTR)BaseDllName.Buffer + i);

            dwModuleHash = ROTR32(dwModuleHash, 13);

            if (*pTempChar >= 0x61)
            {
                dwModuleHash += *pTempChar - 0x20;
            }
            else
            {
                dwModuleHash += *pTempChar;
            }
        }

        pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);

        dwNumFunctions = pExportDir->NumberOfNames;
        pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

        for (i = 0; i < dwNumFunctions; i++)
        {
            dwFunctionHash = 0;
            pFunctionName = (PCSTR)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
            pdwFunctionNameBase++;

            pTempChar = pFunctionName;

            do
            {
                dwFunctionHash = ROTR32(dwFunctionHash, 13);
                dwFunctionHash += *pTempChar;
                pTempChar++;
            } while (*(pTempChar - 1) != 0);

            dwFunctionHash += dwModuleHash;

            if (dwFunctionHash == dwModuleFunctionHash)
            {
                usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
                return (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
            }
        }
    }

    return NULL;
}

void Initfunctions(Pfunctions pfn)
{
    //???LoadLibraryA???????
    pfn->fnLoadLibraryA = (pfnLoadLibraryA)GetProcAddressWithHash(HASH_LoadLibraryA);
    pfn->fnLdrGetProcedureAddress = (pfnLdrGetProcedureAddress)GetProcAddressWithHash(HASH_LdrGetProcedureAddress);;
    pfn->fnNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddressWithHash(HASH_NtAllocateVirtualMemory);;
    pfn->fnLdrLoadDll = (pfnLdrLoadDll)GetProcAddressWithHash(HASH_LdrLoadDll);;
    pfn->fnRtlInitAnsiString = (pfnRtlInitAnsiString)GetProcAddressWithHash(HASH_RtlInitAnsiString);;
    pfn->fnRtlAnsiStringToUnicodeString = (pfnRtlAnsiStringToUnicodeString)GetProcAddressWithHash(HASH_RtlAnsiStringToUnicodeString);;
    pfn->fnRtlFreeUnicodeString = (pfnRtlFreeUnicodeString)GetProcAddressWithHash(HASH_RtlFreeUnicodeString);;


}

