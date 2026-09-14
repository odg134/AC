#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "Telemetry.h"

namespace Telemetry
{
    Packet::Raw Build( const Source& Src )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< HwidPayload* >( Pkt.Payload );

        Pay->IdentityCount = Src.Id->Fill( Pay->Hashes, Identity::MaxEntries );

        Disk::DiskSerial Serials[Disk::MaxDisks]{};
        Pay->DiskCount = Src.DiskInfo->FillSerials( Serials, Disk::MaxDisks );

        for ( ULONG I = 0; I < Pay->DiskCount; ++I )
        {
            Pay->Disks[I].HashAta     = Serials[I].HashAta;
            Pay->Disks[I].HashStorage = Serials[I].HashStorage;
            Pay->Disks[I].Mismatch    =
                ( Serials[I].HashAta && Serials[I].HashStorage &&
                    Serials[I].HashAta != Serials[I].HashStorage ) ? TRUE : FALSE;
        }

        auto& SE  = Pay->SmbiosData;
        auto& Smb = *Src.SmbiosInfo;

        if ( Smb.SystemData( ).Valid )
            RtlCopyMemory( SE.SystemUUID, Smb.SystemData( ).UUID, 16 );

        SE.SystemSerial    = Smb.Hashes( ).SystemSerial;
        SE.BaseboardSerial = Smb.Hashes( ).BaseboardSerial;
        SE.ChassisSerial   = Smb.Hashes( ).ChassisSerial;

        SE.ProcessorCount = Smb.ProcessorData( ).Count;
        RtlCopyMemory( SE.ProcessorHashes, Smb.Hashes( ).ProcessorIds,
            SE.ProcessorCount * sizeof( ULONG64 ) );

        SE.MemoryCount = Smb.MemoryData( ).Count;
        RtlCopyMemory( SE.MemoryHashes, Smb.Hashes( ).MemorySerials,
            SE.MemoryCount * sizeof( ULONG64 ) );

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        Pkt.Hdr.Magic       = Packet::Magic;
        Pkt.Hdr.PacketType  = Packet::Type::Hwid;
        Pkt.Hdr.Version     = 1;
        Pkt.Hdr.Sequence    = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp   = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( HwidPayload );

        return Pkt;
    }
}
