#pragma once
#include <ntddk.h>

namespace Regions::Modules
{
    static constexpr ULONG MaxModules = 256;

    struct Range
    {
        ULONG64 Base;
        ULONG   Size;
    };

    struct Snapshot
    {
        Range Entries[MaxModules];
        ULONG Count;
    };

    /// <summary>
    /// Captures the current loaded-module list via ZwQuerySystemInformation.
    /// Entries are sorted by base address for binary-search use.
    /// </summary>
    /// <param name="Out"></param>
    /// <returns></returns>
    NTSTATUS Capture( Snapshot& Out );

    /// <summary>
    /// Returns true when Va falls within any module range in Snap.
    /// </summary>
    /// <param name="Snap"></param>
    /// <param name="Va"></param>
    /// <returns></returns>
    bool IsInAny( const Snapshot& Snap, ULONG64 Va );
}
