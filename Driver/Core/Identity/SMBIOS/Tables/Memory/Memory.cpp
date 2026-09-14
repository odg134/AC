#include <Misc/Incl.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>
#include "Memory.h"

namespace Memory
{

    static void CopyStr( char* Dst, ULONG DstLen, const char* Src )
    {
        if ( !Src ) { Dst[0] = '\0'; return; }
        ULONG I = 0;
        while ( I < DstLen - 1 && Src[I] ) { Dst[I] = Src[I]; ++I; }
        Dst[I] = '\0';
    }

    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, MemoryInfo* Out )
    {
        *Out = {};
        const UCHAR* End = Table + TableLen;

        for ( const UCHAR* S = Table; S && S < End; S = Tables::NextStruct( S, End ) )
        {
            if ( S[0] != Tables::TypeMemory )
                continue;

            if ( Out->Count >= MaxDevices )
                break;

            if ( S[1] < sizeof( Tables::MemoryDeviceRaw ) )
                continue;

            auto* R = reinterpret_cast< const Tables::MemoryDeviceRaw* >( S );

            auto& D = Out->Devices[Out->Count];

            // Size 0 = not installed; 0xFFFF = unknown.
            //
            D.SizeMb = R->Size;
            D.SpeedMhz = R->Speed;

            CopyStr( D.Manufacturer,  sizeof( D.Manufacturer ),  Tables::GetString( S, R->Manufacturer,  End ) );
            CopyStr( D.SerialNumber,  sizeof( D.SerialNumber ),  Tables::GetString( S, R->SerialNumber,  End ) );
            CopyStr( D.PartNumber,    sizeof( D.PartNumber ),    Tables::GetString( S, R->PartNumber,    End ) );
            CopyStr( D.BankLocator,   sizeof( D.BankLocator ),   Tables::GetString( S, R->BankLocator,   End ) );
            CopyStr( D.DeviceLocator, sizeof( D.DeviceLocator ), Tables::GetString( S, R->DeviceLocator, End ) );

            D.Valid = true;

            if ( R->Size != 0 && R->Size != 0xFFFF )
            {
                ++Out->PopulatedCount;
                Log( "SMBIOS Memory[{}]: bank={} size={} speed={} serial={}",
                    Out->Count, D.BankLocator, D.SizeMb, D.SpeedMhz,
                    Tables::IsJunk( D.SerialNumber ) ? "<junk>" : D.SerialNumber );
            }

            ++Out->Count;
        }

        if ( !Out->Count )
        {
            LogWarn( "SMBIOS Memory: no type 17 structures found" );
            return STATUS_NOT_FOUND;
        }

        Log( "SMBIOS Memory: {} slot(s), {} populated", Out->Count, Out->PopulatedCount );
        return STATUS_SUCCESS;
    }

}
