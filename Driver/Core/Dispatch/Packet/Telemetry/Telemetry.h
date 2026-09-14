#pragma once
#include <ntddk.h>
#include <Core/Identity/Identity.h>
#include <Core/Identity/Disk/Disk.h>
#include <Core/Identity/SMBIOS/SMBIOS.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace Telemetry
{
    struct Source
    {
        const Identity* Id;
        const Disk*     DiskInfo;
        const Smbios*   SmbiosInfo;
    };

#pragma pack(push, 1)
    struct DiskEntry
    {
        ULONG64 HashAta;
        ULONG64 HashStorage;
        BOOLEAN Mismatch;
    };

    struct SmbiosEntry
    {
        UCHAR   SystemUUID[16];    // raw bytes from type 1 structure
        ULONG64 SystemSerial;      // Argon2i hash, 0 if junk/absent
        ULONG64 BaseboardSerial;   // Argon2i hash, 0 if junk/absent
        ULONG64 ChassisSerial;     // Argon2i hash, 0 if junk/absent
        ULONG   ProcessorCount;
        ULONG64 ProcessorHashes[Processor::MaxProcessors];
        ULONG   MemoryCount;
        ULONG64 MemoryHashes[Memory::MaxDevices];
    };

    struct HwidPayload
    {
        ULONG       IdentityCount;
        ULONG64     Hashes[Identity::MaxEntries];
        ULONG       DiskCount;
        DiskEntry   Disks[Disk::MaxDisks];
        SmbiosEntry SmbiosData;
    };
#pragma pack(pop)

    static_assert( sizeof( HwidPayload ) <= Packet::MaxPayload, "HwidPayload exceeds MaxPayload" );

    Packet::Raw Build( const Source& Src );
}
