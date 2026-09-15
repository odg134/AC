#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include <Misc/Hash/Hash.h>
#include "PsModuleList.h"
#include "../Kldr.h"

extern "C" NTSYSAPI LIST_ENTRY PsLoadedModuleList;

static ULONG PeTimeDateStamp( PVOID Base )
{
    __try
    {
        auto* Dos = static_cast<PIMAGE_DOS_HEADER>( Base );
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
            return 0;
        auto* Nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            static_cast<PUCHAR>( Base ) + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
            return 0;
        return Nt->FileHeader.TimeDateStamp;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) { return 0; }
}

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

        auto& E          = m_Entries[m_Count];
        E.HashName       = Hash::Blake2b(
            reinterpret_cast<const UCHAR*>( Ldr->BaseDllName.Buffer ),
            Ldr->BaseDllName.Length );
        E.TimeDateStamp  = Ldr->DllBase ? PeTimeDateStamp( Ldr->DllBase ) : 0;
        ++m_Count;
    }

    return STATUS_SUCCESS;
}
