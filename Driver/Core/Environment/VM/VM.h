#pragma once
#include <ntddk.h>

namespace VM
{
    /// <summary>
    /// Runs the full hypervisor/Hyper-V detection stack:
    /// timing check → CPUID signature → anti-spoof hypercall/MSR layers.
    /// Returns STATUS_UNSUCCESSFUL when a suspicious or spoofed hypervisor
    /// is detected, STATUS_SUCCESS otherwise.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Check( );
}
