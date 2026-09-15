#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include <Core/Offsets/Offsets.h>
#include "UnloadedList.h"

struct MMUNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          StartAddress;
    PVOID          EndAddress;
    LARGE_INTEGER  UnloadTime;
};

NTSTATUS UnloadedList::Collect()
{
    m_Count = 0;

    if ( !Offsets::MmUnloadedDrivers || !Offsets::MmLastUnloadedDriver )
        return STATUS_NOT_FOUND;

    auto* Array = *static_cast<MMUNLOADED_DRIVER**>( static_cast<PVOID>( Offsets::MmUnloadedDrivers ) );
    if ( !Array )
        return STATUS_NOT_FOUND;

    for ( ULONG I = 0; I < 50 && m_Count < MaxEntries; ++I )
    {
        auto& Drv = Array[I];

        if ( !Drv.Name.Buffer || !Drv.Name.Length || !Drv.UnloadTime.QuadPart )
            continue;

        m_Entries[m_Count].HashName      = Hash::Blake2b(
            reinterpret_cast<const UCHAR*>( Drv.Name.Buffer ),
            Drv.Name.Length );
        m_Entries[m_Count].TimeDateStamp = 0;
        ++m_Count;
    }

    return STATUS_SUCCESS;
}
