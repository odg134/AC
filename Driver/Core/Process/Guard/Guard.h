#pragma once
#include <ntddk.h>
#include <Core/Process/Telemetry/ProcTelemetry.h>

namespace Process::Guard
{
    static constexpr ACCESS_MASK StripMask =
        PROCESS_VM_READ       |
        PROCESS_VM_WRITE      |
        PROCESS_VM_OPERATION  |
        PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE    |
        PROCESS_SUSPEND_RESUME;

    OB_PREOP_CALLBACK_STATUS PreOpCallback(
        PVOID Context,
        POB_PRE_OPERATION_INFORMATION Info
    );

    ULONG DrainEvents( Telemetry::AccessEvent* Out, ULONG Max );
}
