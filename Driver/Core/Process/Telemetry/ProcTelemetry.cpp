#include <Misc/Incl.h>
#include "ProcTelemetry.h"

namespace Process::Telemetry
{
    Packet::Raw Build( ULONG ProtectedPid, const AccessEvent* Events, ULONG Count )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< ProcPayload* >( Pkt.Payload );

        Pay->ProtectedPid = ProtectedPid;
        Pay->EventCount   = Count < MaxEvents ? Count : MaxEvents;

        for ( ULONG I = 0; I < Pay->EventCount; ++I )
            Pay->Events[I] = Events[I];

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        Pkt.Hdr.Magic       = Packet::Magic;
        Pkt.Hdr.PacketType  = Packet::Type::Process;
        Pkt.Hdr.Version     = 1;
        Pkt.Hdr.Sequence    = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp   = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( ProcPayload );

        return Pkt;
    }
}
