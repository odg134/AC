#pragma once
#include <ntddk.h>

namespace Memory
{
    static constexpr ULONG MaxDevices = 16;

    struct MemoryDevice
    {
        char   Manufacturer[64];
        char   SerialNumber[64];
        char   PartNumber[64];
        char   BankLocator[64];
        char   DeviceLocator[64];
        USHORT SpeedMhz;
        USHORT SizeMb;     // 0 = slot empty, 0x7FFF = use ExtendedSize
        bool   Valid;
    };

    struct MemoryInfo
    {
        MemoryDevice Devices[MaxDevices];
        ULONG        Count;
        ULONG        PopulatedCount;  // slots that actually contain a DIMM
    };

    /// <summary>
    /// Scans the SMBIOS table for all Type 17 (Memory Device) structures and
    /// collects manufacturer, serial number, part number, and speed per DIMM.
    /// Empty slots (Size == 0) are counted but not included in PopulatedCount.
    /// </summary>
    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, MemoryInfo* Out );
}
