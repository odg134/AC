#include <Misc/Incl.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>
#include "Processor.h"

namespace Processor
{

    static void CopyStr( char* Dst, ULONG DstLen, const char* Src )
    {
        if ( !Src ) { Dst[0] = '\0'; return; }
        ULONG I = 0;
        while ( I < DstLen - 1 && Src[I] ) { Dst[I] = Src[I]; ++I; }
        Dst[I] = '\0';
    }

    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, ProcessorInfo* Out )
    {
        *Out = {};
        const UCHAR* End = Table + TableLen;

        for ( const UCHAR* S = Table; S && S < End; S = Tables::NextStruct( S, End ) )
        {
            if ( S[0] != Tables::TypeProcessor )
                continue;

            if ( Out->Count >= MaxProcessors )
                break;

            if ( S[1] < sizeof( Tables::ProcessorRaw ) )
                continue;

            auto* R = reinterpret_cast< const Tables::ProcessorRaw* >( S );

            // Status byte: bit 6 = CPU socket populated, bits 2:0 = CPU status.
            // Skip unpopulated sockets.
            //
            if ( !( R->Status & 0x40 ) )
                continue;

            auto& E = Out->Entries[Out->Count];

            CopyStr( E.Manufacturer, sizeof( E.Manufacturer ), Tables::GetString( S, R->Manufacturer, End ) );
            CopyStr( E.Version,      sizeof( E.Version ),      Tables::GetString( S, R->Version,      End ) );
            CopyStr( E.Socket,       sizeof( E.Socket ),       Tables::GetString( S, R->SocketDesignation, End ) );

            E.ProcessorId = R->ProcessorId;
            E.MaxSpeedMhz = R->MaxSpeed;
            E.Valid = true;

            Log( "SMBIOS Processor[{}]: manufacturer={} version={} id={:#x} maxMhz={}",
                Out->Count, E.Manufacturer, E.Version, E.ProcessorId, E.MaxSpeedMhz );

            ++Out->Count;
        }

        if ( !Out->Count )
        {
            LogWarn( "SMBIOS Processor: no populated processor sockets found" );
            return STATUS_NOT_FOUND;
        }

        return STATUS_SUCCESS;
    }

}
