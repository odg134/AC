#include <Misc/Incl.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>
#include "Baseboard.h"

namespace Baseboard
{

    static void CopyStr( char* Dst, ULONG DstLen, const char* Src )
    {
        if ( !Src ) { Dst[0] = '\0'; return; }
        ULONG I = 0;
        while ( I < DstLen - 1 && Src[I] ) { Dst[I] = Src[I]; ++I; }
        Dst[I] = '\0';
    }

    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, BaseboardInfo* Out )
    {
        *Out = {};
        const UCHAR* End = Table + TableLen;

        for ( const UCHAR* S = Table; S && S < End; S = Tables::NextStruct( S, End ) )
        {
            if ( S[0] != Tables::TypeBaseboard )
                continue;

            if ( S[1] < sizeof( Tables::BaseboardRaw ) )
                break;

            auto* R = reinterpret_cast< const Tables::BaseboardRaw* >( S );

            CopyStr( Out->Manufacturer, sizeof( Out->Manufacturer ), Tables::GetString( S, R->Manufacturer, End ) );
            CopyStr( Out->Product,      sizeof( Out->Product ),      Tables::GetString( S, R->Product,      End ) );
            CopyStr( Out->Version,      sizeof( Out->Version ),      Tables::GetString( S, R->Version,      End ) );
            CopyStr( Out->SerialNumber, sizeof( Out->SerialNumber ), Tables::GetString( S, R->SerialNumber, End ) );
            CopyStr( Out->AssetTag,     sizeof( Out->AssetTag ),     Tables::GetString( S, R->AssetTag,     End ) );

            Out->Valid = true;

            Log( "SMBIOS Baseboard: manufacturer={} product={} serial={}",
                Out->Manufacturer, Out->Product,
                Tables::IsJunk( Out->SerialNumber ) ? "<junk>" : Out->SerialNumber );

            return STATUS_SUCCESS;
        }

        LogWarn( "SMBIOS Baseboard: type 2 not found" );
        return STATUS_NOT_FOUND;
    }

}
