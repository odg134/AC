#pragma once
#include <ntddk.h>
#include <Core/Process/Telemetry/ProcTelemetry.h>

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ        0x0010
#define PROCESS_VM_WRITE       0x0020
#define PROCESS_VM_OPERATION   0x0008
#define PROCESS_CREATE_THREAD  0x0002
#define PROCESS_DUP_HANDLE     0x0040
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

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
