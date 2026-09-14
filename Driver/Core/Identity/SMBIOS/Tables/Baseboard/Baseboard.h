#pragma once
#include <ntddk.h>

namespace Baseboard
{
    struct BaseboardInfo
    {
        char Manufacturer[64];
        char Product[64];
        char Version[64];
        char SerialNumber[64];
        char AssetTag[64];
        bool Valid;
    };

    /// <summary>
    /// Locates the SMBIOS Type 2 (Baseboard Information) structure and extracts
    /// manufacturer, product, version, serial number, and asset tag fields.
    /// </summary>
    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, BaseboardInfo* Out );
}
