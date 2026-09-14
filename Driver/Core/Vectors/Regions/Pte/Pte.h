#pragma once
#include <ntddk.h>

namespace Regions::Pte
{
    // x64 hardware PTE layout (Vol 3A Table 4-19).
    //
    union HardwarePte
    {
        ULONG64 Value;
        struct
        {
            ULONG64 Present        : 1;
            ULONG64 Writable       : 1;
            ULONG64 UserAccess     : 1;
            ULONG64 WriteThrough   : 1;
            ULONG64 CacheDisable   : 1;
            ULONG64 Accessed       : 1;
            ULONG64 Dirty          : 1;
            ULONG64 LargePage      : 1;
            ULONG64 Global         : 1;
            ULONG64 CopyOnWrite    : 1;
            ULONG64 Prototype      : 1;
            ULONG64 Write          : 1;
            ULONG64 PageFrameNumber : 40;
            ULONG64 Reserved       : 11;
            ULONG64 NoExecute      : 1;
        };
    };
    static_assert( sizeof( HardwarePte ) == 8 );

    /// <summary>
    /// Scans ntoskrnl for MiGetPteAddress to extract the per-boot PTE base.
    /// Must be called once before any Get*() call.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Resolve( );

    /// <summary>
    /// Returns the virtual address of the PTE (4 KB granularity) for Va.
    /// </summary>
    /// <param name="Va"></param>
    /// <returns></returns>
    HardwarePte* GetPte( PVOID Va );

    /// <summary>
    /// Returns the virtual address of the PDE (2 MB granularity) for Va.
    /// </summary>
    /// <param name="Va"></param>
    /// <returns></returns>
    HardwarePte* GetPde( PVOID Va );

    /// <summary>
    /// Returns the virtual address of the PDPTE (1 GB granularity) for Va.
    /// </summary>
    /// <param name="Va"></param>
    /// <returns></returns>
    HardwarePte* GetPdpte( PVOID Va );

    /// <summary>
    /// Returns the virtual address of the PML4E (512 GB granularity) for Va.
    /// </summary>
    /// <param name="Va"></param>
    /// <returns></returns>
    HardwarePte* GetPml4e( PVOID Va );

    /// <summary>
    /// Returns true when the PTE indicates a present, executable page (NX=0).
    /// </summary>
    /// <param name="Pte"></param>
    /// <returns></returns>
    bool IsExecutable( const HardwarePte& Pte );

    /// <summary>
    /// Returns true when the PTE indicates a present, writable, and executable page (RWX).
    /// </summary>
    /// <param name="Pte"></param>
    /// <returns></returns>
    bool IsRwx( const HardwarePte& Pte );
}
