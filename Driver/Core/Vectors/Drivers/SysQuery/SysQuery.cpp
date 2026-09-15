#include <Misc/Incl.h>
#pragma pack(push)
#include <ntimage.h>
#pragma pack(pop)
#include <Misc/Hash/Hash.h>
#include "SysQuery.h"

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

typedef enum _SYSTEM_INFORMATION_CLASS SYSTEM_INFORMATION_CLASS;
extern "C" NTSTATUS ZwQuerySystemInformation( SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG );
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

            auto& E         = m_Entries[m_Count];
            E.HashName      = Hash::Blake2b(
                reinterpret_cast<const UCHAR*>( FullPath + NameOff ),
                FullLen - NameOff );
            E.TimeDateStamp = M.ImageBase ? PeTimeDateStamp( M.ImageBase ) : 0;
            ++m_Count;
        }
    }

    ExFreePoolWithTag( Buf, 'QySM' );
    return St;
}
