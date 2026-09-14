#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace PPL::Telemetry
{
    static constexpr ULONG MaxEntries = 8;

#pragma pack(push, 1)
    struct SnapEntry
    {
        ULONG   Pid;
        UCHAR   ImageName[16];
        UCHAR   ProtectionByte;
        BOOLEAN Anomalous;
        UCHAR   Reserved[2];
    };

    struct PplPayload
    {
        ULONG     GamePid;
        ULONG     EntryCount;
        SnapEntry Entries[MaxEntries];
    };
#pragma pack(pop)

    static_assert( sizeof( PplPayload ) <= Packet::MaxPayload, "PplPayload exceeds MaxPayload" );

    Packet::Raw Build( ULONG GamePid, const SnapEntry* Entries, ULONG Count );
}
