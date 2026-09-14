#pragma once
#include <ntddk.h>

namespace Nic
{
    static constexpr ULONG MaxAdapters   = 8;
    static constexpr ULONG MaxHwIdBytes  = 128;
    static constexpr ULONG MaxGuidBytes  = 78;  // {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} as WCHAR + NUL

    struct NicEntry
    {
        WCHAR  HardwareId[MaxHwIdBytes];   // e.g. PCI\VEN_8086&DEV_15B8
        ULONG  HardwareIdLen;              // character count excluding NUL
        WCHAR  InstanceGuid[MaxGuidBytes]; // NetCfgInstanceId: {GUID}
        ULONG  GuidLen;
        bool   Valid;
    };

    /// <summary>
    /// Enumerates network adapters from the registry class key and collects
    /// hardware IDs and instance GUIDs for each adapter.
    /// Returns the number of entries written to Out.
    /// </summary>
    ULONG Enumerate( NicEntry* Out, ULONG Max );
}
