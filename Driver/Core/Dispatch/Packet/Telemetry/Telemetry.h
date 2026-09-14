#pragma once
#include <ntddk.h>
#include <Core/Identity/Identity.h>
#include <Core/Identity/Disk/Disk.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace Telemetry
{
    struct Source
    {
        const Identity* Id;
        const Disk*     DiskInfo;
    };

    #pragma pack(push, 1)
    struct DiskEntry
    {
        ULONG64 HashAta;
        ULONG64 HashStorage;
        BOOLEAN Mismatch;
    };

    struct HwidPayload
    {
        ULONG     IdentityCount;
        ULONG64   Hashes[Identity::MaxEntries];
        ULONG     DiskCount;
        DiskEntry Disks[Disk::MaxDisks];
    };
    #pragma pack(pop)

    static_assert( sizeof( HwidPayload ) <= Packet::MaxPayload, "HwidPayload exceeds MaxPayload" );

    Packet::Raw Build( const Source& Src );
}
