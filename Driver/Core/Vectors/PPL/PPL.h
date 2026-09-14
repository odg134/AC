#pragma once
#include <ntddk.h>

namespace PPL
{
    NTSTATUS Init();
    void     Shutdown();

    void Snapshot( ULONG GamePid );
}
