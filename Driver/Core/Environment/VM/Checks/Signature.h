#pragma once
#include <ntddk.h>

namespace VM::Signature
{
    /// <summary>
    /// Returns true when CPUID leaf 1 ECX bit 31 (hypervisor-present) is set.
    /// </summary>
    /// <returns></returns>
    bool HvBitPresent( );

    /// <summary>
    /// Returns true when the vendor string from CPUID(0x40000000) equals "Microsoft Hv".
    /// </summary>
    /// <returns></returns>
    bool VendorIsHyperV( );

    /// <summary>
    /// Returns true when CPUID(0x40000001).EAX equals the Hyper-V interface ID
    /// and is not the sentinel value ntoskrnl uses to suppress HV detection.
    /// </summary>
    /// <returns></returns>
    bool IsHyperV( );
}
