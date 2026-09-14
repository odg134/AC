#include <Misc/Incl.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>
#include "System.h"

namespace System
{
    static void CopyStr( char* Dst, ULONG DstLen, const char* Src )
    {
        if ( !Src ) { Dst[0] = '\0'; return; }
        ULONG I = 0;
        while ( I < DstLen - 1 && Src[I] ) { Dst[I] = Src[I]; ++I; }
        Dst[I] = '\0';
    }

    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, SystemInfo* Out )
    {
        *Out = {};
        const UCHAR* End = Table + TableLen;

        for ( const UCHAR* S = Table; S && S < End; S = Tables::NextStruct( S, End ) )
        {
            if ( S[0] != Tables::TypeSystem )
                continue;

            if ( S[1] < sizeof( Tables::SystemRaw ) )
                break;

            auto* R = reinterpret_cast< const Tables::SystemRaw* >( S );

            CopyStr( Out->Manufacturer, sizeof( Out->Manufacturer ), Tables::GetString( S, R->Manufacturer, End ) );
            CopyStr( Out->ProductName, sizeof( Out->ProductName ), Tables::GetString( S, R->ProductName, End ) );
            CopyStr( Out->Version, sizeof( Out->Version ), Tables::GetString( S, R->Version, End ) );
            CopyStr( Out->SerialNumber, sizeof( Out->SerialNumber ), Tables::GetString( S, R->SerialNumber, End ) );
            CopyStr( Out->SKUNumber, sizeof( Out->SKUNumber ), Tables::GetString( S, R->SKUNumber, End ) );
            CopyStr( Out->Family, sizeof( Out->Family ), Tables::GetString( S, R->Family, End ) );

            RtlCopyMemory( Out->UUID, R->UUID, 16 );

            Out->Valid = true;

            Log( "SMBIOS System: manufacturer={} product={} serial={}",
                Out->Manufacturer, Out->ProductName,
                Tables::IsJunk( Out->SerialNumber ) ? "<junk>" : Out->SerialNumber );

            return STATUS_SUCCESS;
        }

        LogWarn( "SMBIOS System: type 1 not found" );
        return STATUS_NOT_FOUND;
    }

}
