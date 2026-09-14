#include <Misc/Incl.h>
#include "PplTelemetry.h"

namespace PPL::Telemetry
{
    Packet::Raw Build( ULONG GamePid, const SnapEntry* Entries, ULONG Count )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< PplPayload* >( Pkt.Payload );

        Pay->GamePid    = GamePid;
        Pay->EntryCount = Count < MaxEntries ? Count : MaxEntries;

        for ( ULONG I = 0; I < Pay->EntryCount; ++I )
            Pay->Entries[I] = Entries[I];

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        Pkt.Hdr.Magic       = Packet::Magic;
        Pkt.Hdr.PacketType  = Packet::Type::Ppl;
        Pkt.Hdr.Version     = 1;
        Pkt.Hdr.Sequence    = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp   = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( PplPayload );

        return Pkt;
    }
}
