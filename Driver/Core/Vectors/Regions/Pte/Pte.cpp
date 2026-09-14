#include <Misc/Incl.h>
#include <Core/Vectors/Regions/Pte/Pte.h>

namespace Regions::Pte
{
    static ULONG64 g_PteBase = 0;

    // Byte pattern for MiGetPteAddress (19 bytes); the next 8 bytes are the PTE base immediate.
    // Matches: shr rcx,9 / mov rax,7FFFFFFFF8h / and rcx,rax / mov rax,<PTE_BASE>
    //
    static constexpr UCHAR Pattern[] = {
        0x48, 0xC1, 0xE9, 0x09,
        0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
        0x48, 0x23, 0xC8,
        0x48, 0xB8
    };
    static constexpr ULONG PatternLen = sizeof( Pattern );

    // Minimal KLDR_DATA_TABLE_ENTRY for walking PsLoadedModuleList.
    //
    struct KldrEntry
    {
        LIST_ENTRY     InLoadOrderLinks;   // +0x000
        PVOID          ExceptionTable;     // +0x010
        ULONG          ExceptionTableSize; // +0x018
        ULONG          Pad0;               // +0x01C
        PVOID          GpValue;            // +0x020
        PVOID          NonPagedDebugInfo;  // +0x028
        PVOID          DllBase;            // +0x030
        PVOID          EntryPoint;         // +0x038
        ULONG          SizeOfImage;        // +0x040
    };

    extern "C" NTKERNELAPI LIST_ENTRY PsLoadedModuleList;

    /// <summary>
    /// Scans ntoskrnl for MiGetPteAddress to extract the per-boot PTE base.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Resolve( )
    {
        // First entry of PsLoadedModuleList is always ntoskrnl.
        //
        auto* Entry = reinterpret_cast< KldrEntry* >( PsLoadedModuleList.Flink );
        if ( !Entry )
            return STATUS_NOT_FOUND;

        auto* Base = reinterpret_cast< UCHAR* >( Entry->DllBase );
        if ( !Base )
            return STATUS_NOT_FOUND;

        auto* Dos = reinterpret_cast< IMAGE_DOS_HEADER* >( Base );
        auto* Nt  = reinterpret_cast< IMAGE_NT_HEADERS* >( Base + Dos->e_lfanew );

        ULONG ScanSize = Nt->OptionalHeader.SizeOfCode;
        ULONG64 CodeStart = reinterpret_cast< ULONG64 >( Base ) + Nt->OptionalHeader.BaseOfCode;

        for ( ULONG i = 0; i + PatternLen + 8 < ScanSize; ++i )
        {
            auto* Ptr = reinterpret_cast< UCHAR* >( CodeStart + i );
            bool Match = true;
            for ( ULONG j = 0; j < PatternLen; ++j )
            {
                if ( Ptr[j] != Pattern[j] )
                {
                    Match = false;
                    break;
                }
            }
            if ( Match )
            {
                g_PteBase = *reinterpret_cast< ULONG64* >( Ptr + PatternLen );
                LogTrace( "Regions: PTE base = {}", reinterpret_cast< void* >( g_PteBase ) );
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    static ULONG64 PteAddressOf( ULONG64 Va )
    {
        return ( ( Va >> 9 ) & 0x7FFFFFFFF8ULL ) + g_PteBase;
    }

    /// <summary>
    /// Returns the virtual address of the PTE for Va.
    /// </summary>
    HardwarePte* GetPte( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) );
    }

    /// <summary>
    /// Returns the virtual address of the PDE for Va.
    /// </summary>
    HardwarePte* GetPde( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >( PteAddressOf( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) ) );
    }

    /// <summary>
    /// Returns the virtual address of the PDPTE for Va.
    /// </summary>
    HardwarePte* GetPdpte( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >(
            PteAddressOf( PteAddressOf( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) ) ) );
    }

    /// <summary>
    /// Returns the virtual address of the PML4E for Va.
    /// </summary>
    HardwarePte* GetPml4e( PVOID Va )
    {
        return reinterpret_cast< HardwarePte* >(
            PteAddressOf( PteAddressOf( PteAddressOf( PteAddressOf( reinterpret_cast< ULONG64 >( Va ) ) ) ) ) );
    }

    /// <summary>
    /// Returns true when the PTE indicates a present, executable page.
    /// </summary>
    bool IsExecutable( const HardwarePte& Pte )
    {
        return Pte.Present && !Pte.NoExecute;
    }

    /// <summary>
    /// Returns true when the PTE indicates a present, writable, executable page.
    /// </summary>
    bool IsRwx( const HardwarePte& Pte )
    {
        return Pte.Present && Pte.Writable && !Pte.NoExecute;
    }
}
