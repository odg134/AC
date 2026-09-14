#pragma once
#include <ntddk.h>

namespace Chassis
{
    struct ChassisInfo
    {
        char  Manufacturer[64];
        char  Version[64];
        char  SerialNumber[64];
        char  AssetTag[64];
        UCHAR ChassisType;   // 0x01 = Other, 0x02 = Unknown, 0x03 = Desktop, etc.
        bool  Valid;
    };

    /// <summary>
    /// Locates the SMBIOS Type 3 (System Enclosure) structure and extracts
    /// manufacturer, version, serial number, asset tag, and chassis type.
    /// </summary>
    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, ChassisInfo* Out );
}
