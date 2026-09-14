#pragma once
#include <ntddk.h>

namespace Processor
{
    static constexpr ULONG MaxProcessors = 8;

    struct ProcessorEntry
    {
        char      Manufacturer[64];
        char      Version[64];
        char      Socket[64];
        ULONGLONG ProcessorId;   // raw 8-byte CPUID value from SMBIOS
        USHORT    MaxSpeedMhz;
        bool      Valid;
    };

    struct ProcessorInfo
    {
        ProcessorEntry Entries[MaxProcessors];
        ULONG          Count;
    };

    /// <summary>
    /// Scans the SMBIOS table for all Type 4 (Processor Information) structures
    /// and collects manufacturer, version, socket, and CPU ID for each one.
    /// </summary>
    NTSTATUS Collect( const UCHAR* Table, ULONG TableLen, ProcessorInfo* Out );
}
