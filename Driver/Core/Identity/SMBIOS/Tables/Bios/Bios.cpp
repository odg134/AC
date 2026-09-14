#include <Misc/Incl.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>
#include "Bios.h"

namespace Bios
{
    static void CopyStr( char* Dst, ULONG DstLen, const char* Src )
    {
        if ( !Src ) { Dst[0] = '\0'; return; }
        ULONG I = 0;
        while ( I < DstLen - 1 && Src[I] ) { Dst[I] = Src[I]; ++I; }
        Dst[I] = '\0';
    }

    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, BiosInfo* Out )
    {
        *Out = {};
        const UCHAR* End = Table + TableLen;

        for ( const UCHAR* S = Table; S && S < End; S = Tables::NextStruct( S, End ) )
        {
            if ( S[0] != Tables::TypeBios )
                continue;

            if ( S[1] < sizeof( Tables::BiosRaw ) )
                break;

            auto* R = reinterpret_cast< const Tables::BiosRaw* >( S );

            CopyStr( Out->Vendor, sizeof( Out->Vendor ), Tables::GetString( S, R->Vendor, End ) );
            CopyStr( Out->Version, sizeof( Out->Version ), Tables::GetString( S, R->BiosVersion, End ) );
            CopyStr( Out->ReleaseDate, sizeof( Out->ReleaseDate ), Tables::GetString( S, R->BiosReleaseDate, End ) );

            Out->MajorRelease = R->MajorRelease;
            Out->MinorRelease = R->MinorRelease;
            Out->Valid = true;

            Log( "SMBIOS Bios: vendor={} version={} release={}.{}",
                Out->Vendor, Out->Version, Out->MajorRelease, Out->MinorRelease );

            return STATUS_SUCCESS;
        }

        LogWarn( "SMBIOS Bios: type 0 not found" );
        return STATUS_NOT_FOUND;
    }

}
