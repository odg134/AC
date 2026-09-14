#include <Misc/Incl.h>
#include <Core/Offsets/Offsets.h>
#include "Mac.h"

namespace Mac
{

    // Safe byte-granularity read with a hard limit to guard against paging issues.
    //
    static bool ReadField( const void* Base, ULONG Offset, void* Out, ULONG Size )
    {
        if ( !Base || Offset + Size < Offset )
            return false;

        __try
        {
            RtlCopyMemory( Out, reinterpret_cast< const UCHAR* >( Base ) + Offset, Size );
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Walks the NDIS global miniport list and collects current and permanent
    /// MAC addresses for each 802.3 adapter by reading NDIS internal structures.
    /// </summary>
    ULONG Collect( MacEntry* Out, ULONG Max )
    {
        if ( !Offsets::NdisMiniportList  ||
             !Offsets::NdisMpNextOffset  ||
             !Offsets::NdisMpIfBlockOffset ||
             !Offsets::NdisIfCurrentMacLen ||
             !Offsets::NdisIfCurrentMac    ||
             !Offsets::NdisIfPermMacLen    ||
             !Offsets::NdisIfPermMac )
        {
            LogWarn( "Mac: NDIS offsets not resolved, skipping" );
            return 0;
        }

        ULONG Count = 0;

        // Read the list head pointer.
        //
        UINT64 MpAddr = 0;
        if ( !ReadField( reinterpret_cast< void* >( Offsets::NdisMiniportList ), 0, &MpAddr, sizeof( MpAddr ) ) )
        {
            LogWarn( "Mac: failed to read ndisMiniportList" );
            return 0;
        }

        while ( MpAddr && Count < Max )
        {
            void* Mp = reinterpret_cast< void* >( MpAddr );

            // Read NDIS_IF_BLOCK* from the miniport block.
            //
            UINT64 IfBlockAddr = 0;
            if ( !ReadField( Mp, Offsets::NdisMpIfBlockOffset, &IfBlockAddr, sizeof( IfBlockAddr ) ) || !IfBlockAddr )
            {
                // Adapter may not have an IF block yet (init in progress); skip it.
                goto next;
            }

            {
                void* IfBlock = reinterpret_cast< void* >( IfBlockAddr );
                MacEntry Entry{};

                // Current MAC.
                //
                USHORT CurrLen = 0;
                ReadField( IfBlock, Offsets::NdisIfCurrentMacLen, &CurrLen, sizeof( CurrLen ) );

                if ( CurrLen > 0 && CurrLen <= MaxMacBytes )
                {
                    Entry.CurrentLen = CurrLen;
                    ReadField( IfBlock, Offsets::NdisIfCurrentMac, Entry.Current, CurrLen );
                }

                // Permanent MAC.
                //
                USHORT PermLen = 0;
                ReadField( IfBlock, Offsets::NdisIfPermMacLen, &PermLen, sizeof( PermLen ) );

                if ( PermLen > 0 && PermLen <= MaxMacBytes )
                {
                    Entry.PermanentLen = PermLen;
                    ReadField( IfBlock, Offsets::NdisIfPermMac, Entry.Permanent, PermLen );
                }

                if ( Entry.CurrentLen > 0 || Entry.PermanentLen > 0 )
                {
                    Entry.Valid    = true;
                    Out[Count++] = Entry;
                    Log( "Mac: adapter {} collected ({}-byte current, {}-byte perm)",
                         Count - 1, Entry.CurrentLen, Entry.PermanentLen );
                }
            }

        next:
            UINT64 Next = 0;
            if ( !ReadField( Mp, Offsets::NdisMpNextOffset, &Next, sizeof( Next ) ) )
                break;

            MpAddr = Next;
        }

        Log( "Mac: {} adapter(s) collected", Count );
        return Count;
    }

}
