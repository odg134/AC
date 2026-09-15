#include <Misc/Incl.h>
#include <Core/Vectors/Drivers/Drivers.h>
#include "Vectors.h"


namespace Vectors
{
    Packet::Raw Build( const Source& Src )
    {
        Packet::Raw Pkt{};
        Pkt.Hdr.Magic      = Packet::Magic;
        Pkt.Hdr.PacketType = Packet::Type::Drivers;
        Pkt.Hdr.Version    = 1;
        Pkt.Hdr.Sequence   = InterlockedIncrement( &Packet::g_Sequence );
        LARGE_INTEGER _Ts; KeQuerySystemTimePrecise( &_Ts );
        Pkt.Hdr.Timestamp  = static_cast<ULONG64>( _Ts.QuadPart );

        auto* Pay = reinterpret_cast<Payload*>( Pkt.Payload );

        if ( Src.DriverInfo )
        {
            Drivers::Entry Tmp[MaxDriverEntries]{};
            ULONG Count      = Src.DriverInfo->FillEntries( Tmp, MaxDriverEntries );
            Pay->DriverCount = Count;

            for ( ULONG I = 0; I < Count; ++I )
            {
                Pay->Drivers[I].HashName      = Tmp[I].HashName;
                Pay->Drivers[I].TimeDateStamp = Tmp[I].TimeDateStamp;
                Pay->Drivers[I].IsUnloaded    = Tmp[I].IsUnloaded ? 1u : 0u;
            }
        }

        Pkt.Hdr.PayloadSize = static_cast<UINT32>(
            sizeof( ULONG ) + Pay->DriverCount * sizeof( DriverEntry ) );

        return Pkt;
    }
}
