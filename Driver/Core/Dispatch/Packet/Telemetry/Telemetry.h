#pragma once
#include <ntddk.h>
#include <Core/Identity/Identity.h>
#include <Core/Identity/Disk/Disk.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace Telemetry
{
    // Carrier for all identity data needed to build a telemetry packet.
    //
    struct Source
    {
        const Identity* Id;
        bool DiskMismatch;
    };

    #pragma pack(push, 1)
    struct HwidPayload
    {
        ULONG   Count;
        ULONG64 Hashes[Identity::MaxEntries];
        BOOLEAN DiskMismatch;
    };
    #pragma pack(pop)

    static_assert( sizeof( HwidPayload ) <= Packet::MaxPayload, "HwidPayload exceeds MaxPayload" );

    Packet::Raw Build( const Source& Src );
}
