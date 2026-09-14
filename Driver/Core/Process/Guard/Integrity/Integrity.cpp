#include <Misc/Incl.h>
#include <Core/Offsets/Offsets.h>
#include "Integrity.h"

namespace Process::Guard::Integrity
{
    // Internal layout of _CALLBACK_ENTRY_ITEM (Windows 10 1903 – Windows 11 24H2).
    //
    struct CallbackEntryItem
    {
        LIST_ENTRY                  EntryItemList;  // +0x00  linked into ObjectType->CallbackList
        OB_OPERATION                Operations;     // +0x10
        LONG                        Enabled;        // +0x14
        PVOID                       CallbackEntry;  // +0x18
        PVOID                       ObjectType;     // +0x20
        POB_PRE_OPERATION_CALLBACK  PreOperation;   // +0x28
        POB_POST_OPERATION_CALLBACK PostOperation;  // +0x30
    };

    static CallbackEntryItem* g_OurEntry{};
    static POB_PRE_OPERATION_CALLBACK g_ExpectedPreOp{};

    // Walk (*PsProcessType)->CallbackList and find the entry whose PreOperation
    // matches the function we registered.
    //
    void Bind( POB_PRE_OPERATION_CALLBACK PreOp )
    {
        g_ExpectedPreOp = PreOp;

        if ( !Offsets::ObjTypeCallbackListOffset || !*PsProcessType )
        {
            LogWarn( "Integrity: cannot bind | ObjTypeCallbackListOffset not resolved" );
            return;
        }

        auto* ListHead = reinterpret_cast< PLIST_ENTRY >(
            reinterpret_cast< PUCHAR >( *PsProcessType ) + Offsets::ObjTypeCallbackListOffset );

        for ( auto* Entry = ListHead->Flink; Entry != ListHead; Entry = Entry->Flink )
        {
            auto* Item = CONTAINING_RECORD( Entry, CallbackEntryItem, EntryItemList );
            if ( Item->PreOperation == PreOp )
            {
                g_OurEntry = Item;
                Log( "Integrity: entry bound at {}", reinterpret_cast< UINT64 >( Item ) );
                return;
            }
        }

        LogWarn( "Integrity: callback entry not found in ObjectType list" );
    }

    // Returns false if our callback entry has been tampered with.
    //
    bool Validate()
    {
        if ( !g_OurEntry )
            return true;

        __try
        {
            // Verify function pointer is intact.
            if ( g_OurEntry->PreOperation != g_ExpectedPreOp )
            {
                LogWarn( "Integrity: PreOperation pointer tampered ({} -> {})",
                    reinterpret_cast< UINT64 >( g_OurEntry->PreOperation ),
                    reinterpret_cast< UINT64 >( g_ExpectedPreOp ) );
                return false;
            }

            // Verify entry is still enabled.
            if ( g_OurEntry->Enabled == 0 )
            {
                LogWarn( "Integrity: callback entry disabled" );
                return false;
            }

            // Verify the entry is still in the list (Flink->Blink must point back).
            PLIST_ENTRY Flink = g_OurEntry->EntryItemList.Flink;
            if ( Flink->Blink != &g_OurEntry->EntryItemList )
            {
                LogWarn( "Integrity: callback entry unlinked from ObjectType list" );
                return false;
            }
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            LogWarn( "Integrity: exception during validation" );
            return false;
        }

        return true;
    }
}
