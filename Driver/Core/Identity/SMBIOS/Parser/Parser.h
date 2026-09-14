#pragma once
#include <ntddk.h>

// Reads the raw SMBIOS table body directly from physical memory using the
// WmipSMBiosTablePhysicalAddress and WmipSMBiosTableLength globals resolved
// by Offsets::Init().  The table is mapped with MmMapIoSpace, copied into a
// NonPagedPool allocation, and then unmapped.

namespace SmbiosParser
{
    static constexpr ULONG PoolTag = 'SMBS';

    struct Table
    {
        UCHAR* Data;
        ULONG  Length;
    };

    /// <summary>
    /// Maps the SMBIOS table from physical memory into a NonPagedPool allocation.
    /// Requires Offsets::WmipSMBiosTablePhysicalAddress and WmipSMBiosTableLength
    /// to have been resolved by Offsets::Init().  Caller must free with FreeTable().
    /// </summary>
    NTSTATUS ReadTable( Table* Out );

    /// <summary>
    /// Frees the buffer returned by ReadTable().
    /// </summary>
    void FreeTable( Table* T );
}
