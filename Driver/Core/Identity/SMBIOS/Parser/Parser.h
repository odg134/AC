#pragma once
#include <ntddk.h>

// Reads the raw SMBIOS table body from the registry key populated by
// mssmbios.sys at boot:
//   \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios\Data
//   value: SMBiosData (REG_BINARY)
//
// The value contains packed SMBIOS structures with no entry-point header.

namespace SmbiosParser
{
    static constexpr ULONG PoolTag = 'SMBS';

    struct Table
    {
        UCHAR* Data;
        ULONG  Length;
    };

    /// <summary>
    /// Reads SMBiosData from the mssmbios registry key into a NonPagedPool
    /// allocation. Caller must free with FreeTable() when done.
    /// </summary>
    NTSTATUS ReadTable( Table* Out );

    /// <summary>
    /// Frees the buffer returned by ReadTable().
    /// </summary>
    void FreeTable( Table* T );
}
