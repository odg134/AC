#pragma once
#include <ntddk.h>

namespace VM::AntiSpoof
{
    /// <summary>
    /// Runs all anti-spoof layers against a hypervisor that already passed the
    /// Hyper-V CPUID signature check. Returns a score in [0, 8]; a score below
    /// 4 means at least one hard hypercall layer failed, indicating a spoof.
    /// </summary>
    /// <returns></returns>
    ULONG ComputeScore( );
}
