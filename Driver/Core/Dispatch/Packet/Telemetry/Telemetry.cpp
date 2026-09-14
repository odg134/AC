#include <Misc/Incl.h>
#include "Telemetry.h"

namespace Telemetry
{
    // Build a telemetry packet...
    //
    Packet::Raw Build( const Source& Src )
    {
        Packet::Raw Pkt{};

        auto* Pay = reinterpret_cast< HwidPayload* >( Pkt.Payload );
        Pay->Count = Src.Id->Fill( Pay->Hashes, Identity::MaxEntries );
        Pay->DiskMismatch = Src.DiskMismatch ? TRUE : FALSE;

        LARGE_INTEGER Now;
        KeQuerySystemTime( &Now );

        Pkt.Hdr.Magic = Packet::Magic;
        Pkt.Hdr.PacketType = Packet::Type::Hwid;
        Pkt.Hdr.Version = 1;
        Pkt.Hdr.Sequence = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( HwidPayload );

        return Pkt;
    }
}
