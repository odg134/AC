#pragma once
#include <ntddk.h>

namespace Process
{
    NTSTATUS Init();
    void     Shutdown();

    void SetProtectedPid( ULONG Pid );
    void ClearProtectedPid( ULONG Pid );

    ULONG GetProtectedPid();
}
