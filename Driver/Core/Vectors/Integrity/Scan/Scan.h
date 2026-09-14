#pragma once
#include <ntddk.h>

namespace Integrity::Scan
{
    static constexpr ULONG MaxModules = 256;
    static constexpr ULONG MaxPathLen = 256;

    struct ModuleEntry
    {
        PVOID  DllBase;
        ULONG  SizeOfImage;
        USHORT FileNameOffset;
        CHAR   FullPath[MaxPathLen];
    };

    struct ModuleList
    {
        ModuleEntry Entries[MaxModules];
        ULONG       Count;
    };

    NTSTATUS Enumerate( ModuleList* Out );

    inline const CHAR* BaseName( const ModuleEntry& E )
    {
        return E.FullPath + E.FileNameOffset;
    }
}
