#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "SysQuery.h"

#define SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)

#pragma warning(push)
#pragma warning(disable: 4200)
struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
};

struct RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[0];
};
#pragma warning(pop)

NTSTATUS SysQuery::Collect()
{
    m_Count = 0;

    ULONG Size = 0;
    ZwQuerySystemInformation( SystemModuleInformation, nullptr, 0, &Size );
    if ( !Size )
        return STATUS_NOT_FOUND;

    Size += 0x1000;
    PVOID Buf = ExAllocatePoolZero( NonPagedPool, Size, 'QySM' );
    if ( !Buf )
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS St = ZwQuerySystemInformation( SystemModuleInformation, Buf, Size, nullptr );
    if ( NT_SUCCESS( St ) )
    {
        auto* Mods = static_cast<RTL_PROCESS_MODULES*>( Buf );
        ULONG N    = min( Mods->NumberOfModules, MaxEntries );

        for ( ULONG I = 0; I < N; ++I )
        {
            auto&  M        = Mods->Modules[I];
            auto*  FullPath = reinterpret_cast<const char*>( M.FullPathName );
            ULONG  FullLen  = static_cast<ULONG>( strnlen( FullPath, sizeof( M.FullPathName ) ) );
            ULONG  NameOff  = M.OffsetToFileName;

            if ( NameOff >= FullLen )
                continue;

            auto& E    = m_Entries[m_Count];
            E.HashName = Hash::Blake2b(
                reinterpret_cast<const UCHAR*>( FullPath + NameOff ),
                FullLen - NameOff );

            if ( FullLen )
                E.HashPath = Hash::Blake2b(
                    reinterpret_cast<const UCHAR*>( FullPath ),
                    FullLen );

            ++m_Count;
        }
    }

    ExFreePoolWithTag( Buf, 'QySM' );
    return St;
}
