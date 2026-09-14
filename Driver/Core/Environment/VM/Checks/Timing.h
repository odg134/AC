#pragma once
#include <ntddk.h>

namespace VM::Timing
{
    /// <summary>
    /// Returns true when the minimum CPUID cycle count across several samples
    /// exceeds the bare-metal ceiling, conclusively indicating a hypervisor.
    /// </summary>
    /// <returns></returns>
    bool ConfirmsHypervisor( );
}
