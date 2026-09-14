#pragma once
#include <ntddk.h>

namespace Mac
{
    static constexpr ULONG MaxAdapters    = 8;
    static constexpr ULONG MaxMacBytes    = 32;

    struct MacEntry
    {
        UCHAR  Current[MaxMacBytes];
        UCHAR  Permanent[MaxMacBytes];
        USHORT CurrentLen;
        USHORT PermanentLen;
        bool   Valid;
    };

    /// <summary>
    /// Walks the NDIS global miniport list and collects current and permanent
    /// MAC addresses for each 802.3 adapter by reading NDIS internal structures.
    /// Requires Offsets::Init() to have resolved the NDIS offsets first.
    /// Returns the number of entries written to Out.
    /// </summary>
    ULONG Collect( MacEntry* Out, ULONG Max );
}
