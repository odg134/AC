#pragma once
#include <ntddk.h>

namespace Regions
{
    /// <summary>
    /// Resolves the per-boot PTE base from ntoskrnl. Must be called once at driver init.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Initialize( );

    /// <summary>
    /// Scans kernel memory for suspicious regions and enqueues a telemetry packet.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Scan( );
}
