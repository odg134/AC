#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include <Core/Vectors/Regions/Scan/PeIntegrity.h>
#include <Core/Vectors/Regions/Pte/Pte.h>

namespace Regions::Scan
{
    static void AddFinding( FindingBuffer& Buf, FindingKind Kind, ULONG64 Va, ULONG64 PteVal )
    {
        if ( Buf.Count >= MaxFindings )
            return;
        Buf.Entries[Buf.Count++] = { Kind, Va, PteVal, PAGE_SIZE };
    }

    static void CheckModule( const Modules::Range& Mod, FindingBuffer& Buf )
    {
        auto* Base = reinterpret_cast< UCHAR* >( Mod.Base );

        if ( !MmIsAddressValid( Base ) )
            return;

        auto* Dos = reinterpret_cast< IMAGE_DOS_HEADER* >( Base );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return;

        auto* Nt = reinterpret_cast< IMAGE_NT_HEADERS* >( Base + Dos->e_lfanew );
        if ( !MmIsAddressValid( Nt ) || Nt->Signature != IMAGE_NT_SIGNATURE )
            return;

        auto* Sections = IMAGE_FIRST_SECTION( Nt );
        USHORT Count   = Nt->FileHeader.NumberOfSections;

        for ( USHORT i = 0; i < Count && Buf.Count < MaxFindings; ++i )
        {
            if ( !( Sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
                continue;

            ULONG64 SecBase = Mod.Base + Sections[i].VirtualAddress;
            ULONG   SecSize = Sections[i].Misc.VirtualSize;

            for ( ULONG64 Va = SecBase; Va < SecBase + SecSize && Buf.Count < MaxFindings; Va += PAGE_SIZE )
            {
                Pte::HardwarePte* Pte = Pte::GetPte( reinterpret_cast< PVOID >( Va ) );
                if ( !MmIsAddressValid( Pte ) )
                    continue;

                // Executable section page with NX set: PTE was flipped after load.
                //
                if ( Pte->Present && Pte->NoExecute )
                    AddFinding( Buf, FindingKind::PteNxFlipped, Va, Pte->Value );
            }
        }
    }

    /// <summary>
    /// Checks PE executable sections of all modules for PTE NX manipulation.
    /// </summary>
    /// <param name="Modules"></param>
    /// <param name="Buffer"></param>
    void CheckPeIntegrity( const Modules::Snapshot& Modules, FindingBuffer& Buffer )
    {
        for ( ULONG i = 0; i < Modules.Count && Buffer.Count < MaxFindings; ++i )
            CheckModule( Modules.Entries[i], Buffer );
    }
}
