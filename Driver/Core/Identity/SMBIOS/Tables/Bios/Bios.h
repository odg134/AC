#pragma once
#include <ntddk.h>

namespace Bios
{
    struct BiosInfo
    {
        char  Vendor[64];
        char  Version[64];
        char  ReleaseDate[32];
        UCHAR MajorRelease;
        UCHAR MinorRelease;
        bool  Valid;
    };

    /// <summary>
    /// Locates the SMBIOS Type 0 (BIOS Information) structure and extracts
    /// vendor, version, release date, and firmware revision fields.
    /// </summary>
    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, BiosInfo* Out );
}
