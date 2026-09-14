#pragma once
#include <ntddk.h>

namespace System
{
    struct SystemInfo
    {
        char  Manufacturer[64];
        char  ProductName[64];
        char  Version[64];
        char  SerialNumber[64];
        char  SKUNumber[64];
        char  Family[64];
        UCHAR UUID[16];   // raw bytes from the SMBIOS table
        bool  Valid;
    };

    /// <summary>
    /// Locates the SMBIOS Type 1 (System Information) structure and extracts
    /// manufacturer, product name, serial number, UUID, SKU, and family fields.
    /// </summary>
    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, SystemInfo* Out );
}
