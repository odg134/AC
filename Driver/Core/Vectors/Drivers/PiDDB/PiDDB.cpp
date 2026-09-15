#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include <Core/Offsets/Offsets.h>
#include "PiDDB.h"

struct PIDDB_CACHE_ENTRY {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    ULONG          TimeDateStamp;
    NTSTATUS       LoadStatus;
};

NTSTATUS PiDDB::Collect()
{
    m_Count = 0;

    if ( !Offsets::PiDDBCacheTable )
        return STATUS_NOT_FOUND;

    auto* Table = static_cast<PRTL_AVL_TABLE>( Offsets::PiDDBCacheTable );

    if ( Offsets::PiDDBLock )
        ExAcquireResourceSharedLite( static_cast<PERESOURCE>( Offsets::PiDDBLock ), TRUE );

    BOOLEAN Restart = TRUE;
    PVOID   Element;
    while ( ( Element = RtlEnumerateGenericTableAvl( Table, Restart ) ) != nullptr
            && m_Count < MaxEntries )
    {
        Restart = FALSE;
        auto* Entry = static_cast<PIDDB_CACHE_ENTRY*>( Element );

        if ( !Entry->DriverName.Buffer || !Entry->DriverName.Length )
            continue;

        m_Entries[m_Count].HashName      = Hash::Blake2b(
            reinterpret_cast<const UCHAR*>( Entry->DriverName.Buffer ),
            Entry->DriverName.Length );
        m_Entries[m_Count].TimeDateStamp = Entry->TimeDateStamp;
        ++m_Count;
    }

    if ( Offsets::PiDDBLock )
        ExReleaseResourceLite( static_cast<PERESOURCE>( Offsets::PiDDBLock ) );

    return STATUS_SUCCESS;
}
