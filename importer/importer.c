#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
} UNICODE_STRING, PUNICODE_STRING;

typedef const UNICODE_STRING
* PCUNICODE_STRING;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID BaseAddress;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
} DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
} PEB, * PPEB;

typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
} TEB, * PTEB;


#ifdef _WIN64
    #define NTCurrentTeb() ((PTEB)__readgsqword(0x30)) // 64-bit offset of TEB at 0x30
#else 
    #define NTCurrentTeb() ((PTEB)__readgsqword(0x18)) // 32-bit offset of TEB at 0x18
#endif // _WIN64

PTEB getTeb(void)
{
    return NTCurrentTeb();
}

/* Compare to wide (Unicode) strings. Returns 0 if equal. */
int cmpstr(WCHAR* str1, WCHAR* str2)
{
    while (*str1 != L'\0' && *str2 != L'\0')
    {
        WCHAR c1 = *str1, c2 = *str2;
        if (c1 >= L'A' && c1 <= L'Z')
            c1 += L'a' - L'A';

        if (c2 >= L'A' && c2 <= L'Z')
            c2 += L'a' - L'A';

        if (c1 != c2)
            return (int)(c1 - c2);

        ++str1;
        ++str2;
    }

    return (int)(*str1 - *str2);
    //while (*str1 && (*str1 == *str2))
    //{
    //    str1++;
    //    str2++;
    //}

    //return *str1 - *str2;
}

unsigned char toLowerC(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    else
        return c;
}

unsigned long djb2Hash(unsigned char* str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
    {
        hash = ((hash << 5) + hash) + toLowerC(c); // hash * 33 + c
    }
    return hash;
} 

/*
    Rewrite of the getModuleHandleA() function that iterates through the 
    PEB's InMemoryOrderModuleList to find a dll.

    Returns a handle to the dll.
*/
HMODULE getModHandle(WCHAR* ModuleName)
{
    //PPEB pPeb = getTeb()->ProcessEnvironmentBlock; // get the TEB
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA PebLdrData = { 0 };
    PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = { 0 };
    PLIST_ENTRY ModuleList = { 0 }, ForwardLink = { 0 };

    if (pPeb)
    {
        PebLdrData = pPeb->Ldr;

        if (PebLdrData)
        {
            //ModuleList = &PebLdrData->InLoadOrderModuleList;
            ModuleList = &PebLdrData->InMemoryOrderModuleList;
            ForwardLink = ModuleList->Flink;

            while (ModuleList != ForwardLink)
            {
                LdrDataTableEntry = CONTAINING_RECORD(ForwardLink-1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (LdrDataTableEntry)
                {
                    if (LdrDataTableEntry->BaseDllName.Buffer)
                    {
                        //if (!cmpstr(LdrDataTableEntry->BaseDllName.Buffer, ModuleName))
                        if (djb2Hash(LdrDataTableEntry->BaseDllName.Buffer) == djb2Hash(ModuleName))
                            return (HMODULE)LdrDataTableEntry->BaseAddress;
                    }
                }
                ForwardLink = ForwardLink->Flink;
            }
        }
    }

    return 0;
}

FARPROC getProcAddr(HMODULE module, LPCSTR lpName)
{
    if (!module || !lpName)
        return -1;

    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)module; // this is the header of the module, in this case the dll
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return -2;

    IMAGE_NT_HEADERS* ntHdrs = (IMAGE_NT_HEADERS*)((BYTE*)module + dosHdr->e_lfanew);
    if (ntHdrs->Signature != IMAGE_NT_SIGNATURE)
        return -3;

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* nameTable = (DWORD*)((BYTE*)module + exportDir->AddressOfNames);
    WORD* ordinalTable = (WORD*)((BYTE*)module + exportDir->AddressOfNameOrdinals);
    DWORD* funcTable = (DWORD*)((BYTE*)module + exportDir->AddressOfFunctions);
    DWORD i;

    if (lpName)
    {
        for (i = 0; i < exportDir->NumberOfNames; i++)
        {
            LPCSTR name = (LPCSTR)((BYTE*)module + nameTable[i]);
            //if (!cmpstr(name, lpName))
            if (djb2Hash(name) == djb2Hash(lpName))
            {
                WORD ordinal = ordinalTable[i];
                DWORD rva = funcTable[ordinal];
                FARPROC ptr = (FARPROC)((BYTE*)module + rva);
                return ptr;
            }
        }
    }
    else
    {
        WORD ord = LOWORD(lpName);
        DWORD rva = funcTable[ord];
        FARPROC ptr = (FARPROC)((BYTE*)module + rva);
        return ptr;
    }
    
    return NULL; // ((void*)0); NULL
}

/*

    Signature of LoadLibraryW from libloaderapi.h:

    HMODULE
    WINAPI
    LoadLibraryW(
        _In_ LPCWSTR lpLibFileName
        );

    Main Entry point to program
*/
int importer()
{
	// kernel32.dll is loaded by default, so I don't think we need to import anything...
	 HMODULE kernelHandle, dll;
     FARPROC print, loader;
     typedef HMODULE(WINAPI* LoadLibraryFunc)(LPCSTR); // function pointer for the LoadLibraryW function

     /* Get handle to kernel32.dll */
     kernelHandle = getModHandle(L"kernel32.dll");
     if (kernelHandle == 0)
         return -10;

     /* Get address of LoadLibraryW function */
     loader = getProcAddr(kernelHandle, "LoadLibraryW");
     if (!loader)
             return -11;

     /* Cast the function pointer from loader to the function pointer typedefe */
     LoadLibraryFunc loadLibrary = (LoadLibraryFunc)loader;

     /* Load the dll with printf in it */
     dll = loadLibrary(L"msvcrt.dll");
     if (!dll)
         return -12;

     /* Get handle to printf */
     print = getProcAddr(dll, "printf");
     if (!print)
         return -14;

     /* Call print */
     print("Hello world.\n");

     return 0;
}