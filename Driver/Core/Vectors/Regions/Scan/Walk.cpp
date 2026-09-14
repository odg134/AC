#include <Misc/Incl.h>
#include <Core/Vectors/Regions/Scan/Walk.h>
#include <Core/Vectors/Regions/Pte/Pte.h>

extern "C" NTKERNELAPI PVOID MmSystemRangeStart;

namespace Regions::Scan
{
    static constexpr ULONG64 Step2M  = 0x200000ULL;
    static constexpr ULONG64 Step1G  = 0x40000000ULL;
    static constexpr ULONG64 Step512G = 0x8000000000ULL;

    static void AddFinding( FindingBuffer& Buf, FindingKind Kind, ULONG64 Va, ULONG64 PteVal, ULONG Size = PAGE_SIZE )
    {
        if ( Buf.Count >= MaxFindings )
            return;
        Buf.Entries[Buf.Count++] = { Kind, Va, PteVal, Size };
    }

    static void CheckPage( ULONG64 Va, const Pte::HardwarePte& Pte,
                           const Modules::Snapshot& Modules, FindingBuffer& Buf )
    {
        if ( Pte::IsRwx( Pte ) )
            AddFinding( Buf, FindingKind::Rwx, Va, Pte.Value );

        if ( Pte::IsExecutable( Pte ) && !Modules::IsInAny( Modules, Va ) )
            AddFinding( Buf, FindingKind::UnbackedExecutable, Va, Pte.Value );
    }

    /// <summary>
    /// Walks the kernel VA space hierarchically, flagging suspicious pages.
    /// </summary>
    /// <param name="Modules"></param>
    /// <param name="Buffer"></param>
    void Execute( const Modules::Snapshot& Modules, FindingBuffer& Buffer )
    {
        Buffer.Count = 0;

        ULONG64 Va      = reinterpret_cast< ULONG64 >( MmSystemRangeStart );
        ULONG64 PteRegionStart = reinterpret_cast< ULONG64 >( Pte::GetPte( nullptr ) ) & ~( Step512G - 1 );
        ULONG64 PteRegionEnd   = PteRegionStart + Step512G;

        while ( Va < 0xFFFFFFFFFFFF0000ULL && Buffer.Count < MaxFindings )
        {
            // Skip the PTE self-mapping region to avoid false positives and recursion.
            //
            if ( Va >= PteRegionStart && Va < PteRegionEnd )
            {
                Va = PteRegionEnd;
                continue;
            }

            // PML4E | 512 GB granularity.
            //
            Pte::HardwarePte* Pml4e = Pte::GetPml4e( reinterpret_cast< PVOID >( Va ) );
            if ( !MmIsAddressValid( Pml4e ) || !Pml4e->Present )
            {
                Va = ( Va & ~( Step512G - 1 ) ) + Step512G;
                continue;
            }

            // PDPTE | 1 GB granularity.
            //
            Pte::HardwarePte* Pdpte = Pte::GetPdpte( reinterpret_cast< PVOID >( Va ) );
            if ( !Pdpte->Present )
            {
                Va = ( Va & ~( Step1G - 1 ) ) + Step1G;
                continue;
            }
            if ( Pdpte->LargePage )
            {
                CheckPage( Va & ~( Step1G - 1 ), *Pdpte, Modules, Buffer );
                Va = ( Va & ~( Step1G - 1 ) ) + Step1G;
                continue;
            }

            // PDE | 2 MB granularity.
            //
            Pte::HardwarePte* Pde = Pte::GetPde( reinterpret_cast< PVOID >( Va ) );
            if ( !Pde->Present )
            {
                Va = ( Va & ~( Step2M - 1 ) ) + Step2M;
                continue;
            }
            if ( Pde->LargePage )
            {
                CheckPage( Va & ~( Step2M - 1 ), *Pde, Modules, Buffer );
                Va = ( Va & ~( Step2M - 1 ) ) + Step2M;
                continue;
            }

            // PTE | walk all 512 entries in this 2 MB region.
            //
            ULONG64 Aligned = Va & ~( Step2M - 1 );
            for ( ULONG64 PtVa = Aligned; PtVa < Aligned + Step2M && Buffer.Count < MaxFindings; PtVa += PAGE_SIZE )
            {
                Pte::HardwarePte* Pte = Pte::GetPte( reinterpret_cast< PVOID >( PtVa ) );
                if ( Pte->Present )
                    CheckPage( PtVa, *Pte, Modules, Buffer );
            }

            Va = Aligned + Step2M;
        }
    }
}
