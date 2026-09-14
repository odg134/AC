#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>
#include <Core/Vectors/Integrity/Integrity.h>

namespace Integrity::Telemetry
{
#pragma pack(push, 1)
    struct IntegrityPayload
    {
        ULONG   FindingCount;
        Finding Findings[MaxFindings];
    };
#pragma pack(pop)

    static_assert( sizeof( IntegrityPayload ) <= Packet::MaxPayload,
        "IntegrityPayload exceeds MaxPayload" );

    Packet::Raw Build( const FindingList& Findings );
}
