#pragma once
#include <ntddk.h>
#include <Core/Identity/Identity.h>
#include <Core/Identity/Disk/Disk.h>
#include <Core/Identity/SMBIOS/SMBIOS.h>
#include <Core/Identity/Network/Network.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace Telemetry
{
    struct Source
    {
        const Identity* Id;
        const Disk*     DiskInfo;
        const Smbios*   SmbiosInfo;
        const Network*  NetworkInfo;
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

    // Two adapter slots; enough for most machines while keeping the payload under MaxPayload.
    //
    static constexpr ULONG MaxNetworkAdapters = 2;

    struct NetworkEntry
    {
        ULONG64 HashCurrentMac;
        ULONG64 HashPermanentMac;
        BOOLEAN MacMismatch;
    };

    struct DnsData
    {
        ULONG64 HashDomain;
        ULONG64 HashHostname;
    };

    struct HwidPayload
    {
        ULONG        IdentityCount;
        ULONG64      Hashes[Identity::MaxEntries];
        ULONG        DiskCount;
        DiskEntry    Disks[Disk::MaxDisks];
        SmbiosEntry  SmbiosData;
        ULONG        NetworkCount;
        NetworkEntry NetworkAdapters[MaxNetworkAdapters];
        DnsData      DnsInfo;
    };
#pragma pack(pop)

    static_assert( sizeof( HwidPayload ) <= Packet::MaxPayload, "HwidPayload exceeds MaxPayload" );

    Packet::Raw Build( const Source& Src );
}
