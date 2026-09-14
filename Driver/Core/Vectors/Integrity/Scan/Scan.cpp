#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include "Scan.h"

extern "C" NTSTATUS ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength );

namespace Integrity::Scan
{
    static constexpr ULONG SystemModuleInformation = 11;

    struct RawEntry
    {
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

    struct RawList
    {
        ULONG    Count;
        RawEntry Modules[1];
    };

    NTSTATUS Enumerate( ModuleList* Out )
    {
        ULONG Needed = 0;
        ZwQuerySystemInformation( SystemModuleInformation, nullptr, 0, &Needed );
        if ( !Needed )
            return STATUS_UNSUCCESSFUL;

        Needed += 1024;
        Mem::RawPtr Buf( Needed );
        if ( !Buf )
            return STATUS_INSUFFICIENT_RESOURCES;

        NTSTATUS Status = ZwQuerySystemInformation(
            SystemModuleInformation, Buf.As<RawList>(), Needed, nullptr );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        auto* List = Buf.As<RawList>();
        Out->Count = 0;

        for ( ULONG i = 0; i < List->Count && Out->Count < MaxModules; ++i )
        {
            auto& Src = List->Modules[i];
            auto& Dst = Out->Entries[Out->Count];

            Dst.DllBase       = Src.ImageBase;
            Dst.SizeOfImage   = Src.ImageSize;
            Dst.FileNameOffset = Src.OffsetToFileName;

            ULONG Len = 0;
            while ( Src.FullPathName[Len] && Len < MaxPathLen - 1 )
                ++Len;

            RtlCopyMemory( Dst.FullPath, Src.FullPathName, Len );
            Dst.FullPath[Len] = '\0';

            ++Out->Count;
        }

        return STATUS_SUCCESS;
    }
}
