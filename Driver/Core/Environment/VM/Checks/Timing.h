#pragma once
#include <ntddk.h>

namespace VM::Timing
{
    /// <summary>
    /// Returns the minimum RDTSC delta across several CPUID leaf 1 samples.
    /// </summary>
    /// <returns></returns>
    ULONG64 MeasureMinCycles( );

    /// <summary>
    /// Returns true when MeasureMinCycles() exceeds the bare-metal ceiling,
    /// conclusively indicating a hypervisor.
    /// </summary>
    /// <returns></returns>
    bool ConfirmsHypervisor( );
}
