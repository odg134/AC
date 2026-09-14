#pragma once
#include <ntddk.h>

namespace PG
{
    /// <summary>
    /// Resolve all offsets.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Initialize( );

    /// <summary>
    /// Verify PatchGuard/KPP's integrity and
    /// that it has not been tampered with.
    /// </summary>
    /// <returns></returns>
    NTSTATUS VerifyPresence( );

}
