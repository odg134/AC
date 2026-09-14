#include <Misc/Incl.h>
#include <Core/Vectors/Regions/Modules/Modules.h>
#include <Core/Mem/Mem.h>

namespace Regions::Modules
{
    static constexpr ULONG SystemModuleInformation = 11;

    struct RtlModuleInfo
    {
        HANDLE  Section;
        PVOID   MappedBase;
        PVOID   ImageBase;
        ULONG   ImageSize;
        ULONG   Flags;
        USHORT  LoadOrderIndex;
        USHORT  InitOrderIndex;
        USHORT  LoadCount;
        USHORT  OffsetToFileName;
        UCHAR   FullPathName[256];
    };

    struct RtlModuleList
    {
        ULONG         Count;
        RtlModuleInfo Modules[1];
    };

    extern "C" NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
        ULONG  SystemInformationClass,
        PVOID  SystemInformation,
        ULONG  SystemInformationLength,
        PULONG ReturnLength );

    static int CompareRange( const void* A, const void* B )
    {
        const Range* Ra = static_cast< const Range* >( A );
        const Range* Rb = static_cast< const Range* >( B );
        if ( Ra->Base < Rb->Base ) return -1;
        if ( Ra->Base > Rb->Base ) return  1;
        return 0;
    }

    /// <summary>
    /// Captures the current loaded-module list via ZwQuerySystemInformation.
    /// </summary>
    /// <param name="Out"></param>
    /// <returns></returns>
    NTSTATUS Capture( Snapshot& Out )
    {
        Out.Count = 0;

        ULONG Needed = 0;
        ZwQuerySystemInformation( SystemModuleInformation, nullptr, 0, &Needed );
        if ( !Needed )
            return STATUS_UNSUCCESSFUL;

        Needed += 4096;
        Mem::RawPtr Buf( Needed );
        if ( !Buf )
            return STATUS_INSUFFICIENT_RESOURCES;

        NTSTATUS S = ZwQuerySystemInformation(
            SystemModuleInformation,
            Buf.As< VOID >( ),
            Needed,
            &Needed );

        if ( !NT_SUCCESS( S ) )
            return S;

        auto* List = Buf.As< RtlModuleList >( );

        for ( ULONG i = 0; i < List->Count && Out.Count < MaxModules; ++i )
        {
            const RtlModuleInfo& M = List->Modules[i];
            if ( !M.ImageBase || !M.ImageSize )
                continue;

            Out.Entries[Out.Count].Base = reinterpret_cast< ULONG64 >( M.ImageBase );
            Out.Entries[Out.Count].Size = M.ImageSize;
            ++Out.Count;
        }

        // Sort by base for binary search.
        //
        qsort( Out.Entries, Out.Count, sizeof( Range ), CompareRange );
        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Returns true when Va falls within any module range.
    /// </summary>
    /// <param name="Snap"></param>
    /// <param name="Va"></param>
    /// <returns></returns>
    bool IsInAny( const Snapshot& Snap, ULONG64 Va )
    {
        LONG Lo = 0, Hi = static_cast< LONG >( Snap.Count ) - 1;
        while ( Lo <= Hi )
        {
            LONG Mid = Lo + ( Hi - Lo ) / 2;
            const Range& R = Snap.Entries[Mid];
            if ( Va >= R.Base && Va < R.Base + R.Size )
                return true;
            if ( Va < R.Base )
                Hi = Mid - 1;
            else
                Lo = Mid + 1;
        }
        return false;
    }
}
