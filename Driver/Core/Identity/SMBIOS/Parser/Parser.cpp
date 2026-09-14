#include <Misc/Incl.h>
#include <Core/Offsets/Offsets.h>
#include "Parser.h"

namespace SmbiosParser
{

    NTSTATUS ReadTable( Table* Out )
    {
        *Out = {};

        if ( !Offsets::WmipSMBiosTablePhysicalAddress || !Offsets::WmipSMBiosTableLength )
        {
            LogError( "SmbiosParser: SMBIOS offsets not resolved" );
            return STATUS_NOT_FOUND;
        }

        PHYSICAL_ADDRESS Pa;
        Pa.QuadPart = static_cast< LONGLONG >( *Offsets::WmipSMBiosTablePhysicalAddress );
        ULONG Len   = *Offsets::WmipSMBiosTableLength;

        if ( !Pa.QuadPart || !Len )
        {
            LogError( "SmbiosParser: SMBIOS globals are zero (not populated yet)" );
            return STATUS_NOT_FOUND;
        }

        PVOID Mapped = MmMapIoSpace( Pa, Len, MmCached );
        if ( !Mapped )
        {
            LogError( "SmbiosParser: MmMapIoSpace failed (pa={} len={})", Pa.QuadPart, Len );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        UCHAR* Blob = static_cast< UCHAR* >(
            ExAllocatePoolWithTag( NonPagedPool, Len, PoolTag ) );

        if ( !Blob )
        {
            MmUnmapIoSpace( Mapped, Len );
            LogError( "SmbiosParser: blob allocation failed ({} bytes)", Len );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory( Blob, Mapped, Len );
        MmUnmapIoSpace( Mapped, Len );

        Out->Data   = Blob;
        Out->Length = Len;

        Log( "SmbiosParser: mapped {} byte(s) from pa={:#x}", Len, Pa.QuadPart );
        return STATUS_SUCCESS;
    }

    void FreeTable( Table* T )
    {
        if ( T->Data )
        {
            ExFreePoolWithTag( T->Data, PoolTag );
            *T = {};
        }
    }

}
