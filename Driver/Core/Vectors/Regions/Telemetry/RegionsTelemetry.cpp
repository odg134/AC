#include <Misc/Incl.h>
#include <Core/Vectors/Regions/Telemetry/RegionsTelemetry.h>

namespace Regions::Telemetry
{
    /// <summary>
    /// Serialises a FindingBuffer into a Packet::Raw ready to enqueue.
    /// </summary>
    /// <param name="Buf"></param>
    /// <returns></returns>
    Packet::Raw Build( const Scan::FindingBuffer& Buf )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< RegionsPayload* >( Pkt.Payload );

        Pay->Count = Buf.Count;
        for ( ULONG i = 0; i < Buf.Count; ++i )
        {
            Pay->Findings[i].Kind       = static_cast< ULONG >( Buf.Entries[i].Kind );
            Pay->Findings[i].Va         = Buf.Entries[i].Va;
            Pay->Findings[i].PteValue   = Buf.Entries[i].PteValue;
            Pay->Findings[i].RegionSize = Buf.Entries[i].RegionSize;
        }

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        Pkt.Hdr.Magic       = Packet::Magic;
        Pkt.Hdr.PacketType  = Packet::Type::Regions;
        Pkt.Hdr.Version     = 1;
        Pkt.Hdr.Sequence    = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp   = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( RegionsPayload );

        return Pkt;
    }
}
