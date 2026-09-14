#pragma once
#include "../../../../../Shared/IOCTL/IOCTL.h"

namespace IOCTL
{
    NTSTATUS Heartbeat( PIRP Irp, PIO_STACK_LOCATION Stack );
    NTSTATUS ProtectProcess( PIRP Irp, PIO_STACK_LOCATION Stack );
    NTSTATUS UnprotectProcess( PIRP Irp, PIO_STACK_LOCATION Stack );
    NTSTATUS QueryProtection( PIRP Irp, PIO_STACK_LOCATION Stack );
}
