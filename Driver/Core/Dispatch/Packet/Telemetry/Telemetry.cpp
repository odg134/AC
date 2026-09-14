#include <Misc/Incl.h>
#include "Telemetry.h"

namespace Telemetry
{
    Packet::Raw Build( const Source& Src )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< HwidPayload* >( Pkt.Payload );

        Pay->IdentityCount = Src.Id->Fill( Pay->Hashes, Identity::MaxEntries );

        // Send all disks...
        //
        Disk::DiskSerial Serials[Disk::MaxDisks]{};
        Pay->DiskCount = Src.DiskInfo->FillSerials( Serials, Disk::MaxDisks );

        for ( ULONG I = 0; I < Pay->DiskCount; ++I )
        {
            Pay->Disks[I].HashAta = Serials[I].HashAta;
            Pay->Disks[I].HashStorage = Serials[I].HashStorage;
            Pay->Disks[I].Mismatch =
                ( Serials[I].HashAta && Serials[I].HashStorage &&
                    Serials[I].HashAta != Serials[I].HashStorage ) ? TRUE : FALSE;
        }

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        // Setup the packet data...
        Pkt.Hdr.Magic = Packet::Magic;
        Pkt.Hdr.PacketType = Packet::Type::Hwid;
        Pkt.Hdr.Version = 1;
        Pkt.Hdr.Sequence = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( HwidPayload );

        return Pkt;
    }
}
