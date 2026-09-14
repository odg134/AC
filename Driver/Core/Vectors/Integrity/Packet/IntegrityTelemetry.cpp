#include <Misc/Incl.h>
#include "IntegrityTelemetry.h"

namespace Integrity::Telemetry
{
    Packet::Raw Build( const FindingList& Findings )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< IntegrityPayload* >( Pkt.Payload );

        ULONG Count = min( Findings.Count, MaxFindings );
        Pay->FindingCount = Count;
        RtlCopyMemory( Pay->Findings, Findings.Entries, Count * sizeof( Finding ) );

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        Pkt.Hdr.Magic       = Packet::Magic;
        Pkt.Hdr.PacketType  = Packet::Type::Integrity;  // 4
        Pkt.Hdr.Version     = 1;
        Pkt.Hdr.Sequence    = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp   = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( IntegrityPayload );

        return Pkt;
    }
}
