#include <Misc/Incl.h>
#include <intrin.h>
#include <Core/Environment/VM/Hypercall/Hypercall.h>

// clang-cl emits a call to __writemsr instead of inlining it; provide the definition
extern "C" void __writemsr( unsigned long Reg, unsigned __int64 Value )
{
    __asm__ volatile( "wrmsr" :: "c"(Reg), "a"((unsigned)(Value)), "d"((unsigned)(Value >> 32)) );
}

namespace Hypercall
{
    using HypercallFn = ULONG64 (*)( ULONG64, ULONG64, ULONG64 );

    static PVOID            s_HypercallVa   = nullptr;
    static HypercallFn      s_HypercallExec = nullptr;
    static PVOID            s_InputPage     = nullptr;
    static PVOID            s_OutputPage    = nullptr;
    static PHYSICAL_ADDRESS s_InputGpa      = {};
    static PHYSICAL_ADDRESS s_OutputGpa     = {};
    static ULONG64          s_SavedMsr      = 0;

    /// <summary>
    /// Allocates the input/output transfer pages and maps the hypercall page
    /// by writing MSR 0x40000001.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Initialize( )
    {
        PHYSICAL_ADDRESS MaxPhys = {};
        MaxPhys.QuadPart = MAXLONGLONG;

        s_HypercallVa = MmAllocateContiguousMemory( PAGE_SIZE, MaxPhys );
        if ( !s_HypercallVa )
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory( s_HypercallVa, PAGE_SIZE );

        PHYSICAL_ADDRESS HcGpa = MmGetPhysicalAddress( s_HypercallVa );

        // MmMapIoSpaceEx creates an executable alias of the same GPA for calling the stub.
        //
        s_HypercallExec = reinterpret_cast< HypercallFn >(
            MmMapIoSpaceEx( HcGpa, PAGE_SIZE, PAGE_EXECUTE_READ ) );

        if ( !s_HypercallExec )
        {
            Cleanup( );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        s_InputPage = MmAllocateContiguousMemory( PAGE_SIZE, MaxPhys );
        if ( !s_InputPage )
        {
            Cleanup( );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        s_OutputPage = MmAllocateContiguousMemory( PAGE_SIZE, MaxPhys );
        if ( !s_OutputPage )
        {
            Cleanup( );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        s_InputGpa  = MmGetPhysicalAddress( s_InputPage );
        s_OutputGpa = MmGetPhysicalAddress( s_OutputPage );

        // ntoskrnl owns its own hypercall page; save and restore on teardown.
        //
        s_SavedMsr = __readmsr( MsrHypercallPage );

        ULONG64 NewMsr = ( HcGpa.QuadPart & ~0xFFFLL ) | ( s_SavedMsr & 0x2ULL ) | 0x1ULL;
        __writemsr( MsrHypercallPage, NewMsr );

        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Restores MSR 0x40000001 to its original value and frees all memory.
    /// </summary>
    void Cleanup( )
    {
        if ( s_SavedMsr )
        {
            __writemsr( MsrHypercallPage, s_SavedMsr );
            s_SavedMsr = 0;
        }

        if ( s_HypercallExec )
        {
            MmUnmapIoSpace( reinterpret_cast< PVOID >( s_HypercallExec ), PAGE_SIZE );
            s_HypercallExec = nullptr;
        }

        if ( s_HypercallVa )
        {
            MmFreeContiguousMemory( s_HypercallVa );
            s_HypercallVa = nullptr;
        }

        if ( s_InputPage )
        {
            MmFreeContiguousMemory( s_InputPage );
            s_InputPage = nullptr;
        }

        if ( s_OutputPage )
        {
            MmFreeContiguousMemory( s_OutputPage );
            s_OutputPage = nullptr;
        }
    }

    /// <summary>
    /// Issues a memory-based hypercall through the hypercall page stub.
    /// </summary>
    /// <param name="Code"></param>
    /// <param name="Input"></param>
    /// <param name="InputSize"></param>
    /// <param name="Output"></param>
    /// <param name="OutputSize"></param>
    /// <param name="HvStatus"></param>
    /// <returns></returns>
    NTSTATUS Invoke( USHORT Code, const void* Input, ULONG InputSize, void* Output, ULONG OutputSize, USHORT* HvStatus )
    {
        if ( !s_HypercallExec || !s_InputPage || !s_OutputPage )
            return STATUS_DEVICE_NOT_READY;

        RtlZeroMemory( s_InputPage,  PAGE_SIZE );
        RtlZeroMemory( s_OutputPage, PAGE_SIZE );

        if ( Input && InputSize )
            RtlCopyMemory( s_InputPage, Input, InputSize );

        HypercallInput In = {};
        In.CallCode = Code;

        HypercallOutput Out = {};
        Out.Value = s_HypercallExec( In.Value, s_InputGpa.QuadPart, s_OutputGpa.QuadPart );

        if ( HvStatus )
            *HvStatus = static_cast< USHORT >( Out.Status );

        if ( Out.Status != HvStatusSuccess )
            return STATUS_UNSUCCESSFUL;

        if ( Output && OutputSize )
            RtlCopyMemory( Output, s_OutputPage, OutputSize );

        return STATUS_SUCCESS;
    }
}
