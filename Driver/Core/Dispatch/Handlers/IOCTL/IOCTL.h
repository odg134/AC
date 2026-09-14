#pragma once
#include <ntddk.h>

// Define the main IOCTL codes...
//
#define IOCTL_HEARTBEAT CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_PROTECT_PROCESS CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_UNPROTECT_PROCESS CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_QUERY_PROTECTION CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS )

namespace IOCTL
{
    struct HeartbeatResponse
    {
        ULONG Version;
        BOOLEAN Protected;
    };

    struct ProtectRequest
    {
        ULONG Pid;
    };

    struct UnprotectRequest
    {
        ULONG Pid;
    };

    struct QueryRequest
    {
        ULONG Pid;
    };

    struct QueryResponse
    {
        BOOLEAN Protected;
    };

    NTSTATUS Heartbeat( PIRP Irp, PIO_STACK_LOCATION Stack );
    NTSTATUS ProtectProcess( PIRP Irp, PIO_STACK_LOCATION Stack );
    NTSTATUS UnprotectProcess( PIRP Irp, PIO_STACK_LOCATION Stack );
    NTSTATUS QueryProtection( PIRP Irp, PIO_STACK_LOCATION Stack );
}
