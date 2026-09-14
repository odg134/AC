#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>
#include <Core/Vectors/Regions/Scan/Walk.h>

namespace Regions::Telemetry
{
#pragma pack(push, 1)
    struct RegionFinding
    {
        ULONG   Kind;
        ULONG64 Va;
        ULONG64 PteValue;
        ULONG   RegionSize;
    };

    struct RegionsPayload
    {
        ULONG         Count;
        RegionFinding Findings[Scan::MaxFindings];
    };
#pragma pack(pop)

    static_assert( sizeof( RegionsPayload ) <= Packet::MaxPayload, "RegionsPayload exceeds MaxPayload" );

    /// <summary>
    /// Serialises a FindingBuffer into a Packet::Raw ready to enqueue.
    /// </summary>
    /// <param name="Buf"></param>
    /// <returns></returns>
    Packet::Raw Build( const Scan::FindingBuffer& Buf );
}
