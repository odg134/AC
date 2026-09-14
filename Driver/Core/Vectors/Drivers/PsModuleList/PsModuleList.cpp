#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "PsModuleList.h"
#include "../Kldr.h"

extern "C" NTSYSAPI LIST_ENTRY PsLoadedModuleList;

NTSTATUS PsModuleList::Collect()
{
    m_Count = 0;

    for ( LIST_ENTRY* Link = PsLoadedModuleList.Flink;
          Link != &PsLoadedModuleList && m_Count < MaxEntries;
          Link = Link->Flink )
    {
        auto* Ldr = CONTAINING_RECORD( Link, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

        if ( !Ldr->BaseDllName.Buffer || !Ldr->BaseDllName.Length )
            continue;

        auto& E   = m_Entries[m_Count];
        E.HashName = Hash::Blake2b(
            reinterpret_cast<const UCHAR*>( Ldr->BaseDllName.Buffer ),
            Ldr->BaseDllName.Length );

        if ( Ldr->FullDllName.Buffer && Ldr->FullDllName.Length )
            E.HashPath = Hash::Blake2b(
                reinterpret_cast<const UCHAR*>( Ldr->FullDllName.Buffer ),
                Ldr->FullDllName.Length );

        ++m_Count;
    }

    return STATUS_SUCCESS;
}
