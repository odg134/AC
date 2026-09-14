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
    /// Returns true when the hypervisor vendor string, interface ID,
    /// and sentinel exclusion all match genuine Hyper-V.
    /// </summary>
    /// <returns></returns>
    bool IsHyperV( );
}
