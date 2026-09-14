#pragma once
#include <ntddk.h>
#include <Core/Vectors/Regions/Modules/Modules.h>

namespace Regions::Scan
{
    static constexpr ULONG MaxFindings = 21;

    enum class FindingKind : ULONG
    {
        UnbackedExecutable = 1,  // executable page not backed by any loaded module
        Rwx                = 2,  // present + writable + executable
        PteNxFlipped       = 3,  // PE executable section page with NX set in PTE
    };

    struct Finding
    {
        FindingKind Kind;
        ULONG64     Va;
        ULONG64     PteValue;
        ULONG       RegionSize;
    };

    struct FindingBuffer
    {
        Finding Entries[MaxFindings];
        ULONG   Count;
    };

    /// <summary>
    /// Walks the kernel VA space from MmSystemRangeStart hierarchically via the PTE
    /// mapping, flagging executable pages not covered by any module and RWX pages.
    /// </summary>
    /// <param name="Modules"></param>
    /// <param name="Buffer"></param>
    void Execute( const Modules::Snapshot& Modules, FindingBuffer& Buffer );
}
