#include <Misc/Incl.h>
#include <Core/Dispatch/Dispatch.h>
#include <Core/Dispatch/Handlers/IOCTL/IOCTL.h>

/// <summary>
/// </summary>
/// <param name="DeviceObject"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS DispatchCreate( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
    UNREFERENCED_PARAMETER( DeviceObject );

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

/// <summary>
/// </summary>
/// <param name="DeviceObject"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS DispatchClose( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
    UNREFERENCED_PARAMETER( DeviceObject );

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

/// <summary>
/// </summary>
/// <param name="DeviceObject"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS DispatchControl( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
    UNREFERENCED_PARAMETER( DeviceObject );

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation( Irp );
    ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    switch ( Code )
    {
    case IOCTL_HEARTBEAT:         Status = IOCTL::Heartbeat( Irp, Stack );         break;
    case IOCTL_PROTECT_PROCESS:   Status = IOCTL::ProtectProcess( Irp, Stack );    break;
    case IOCTL_UNPROTECT_PROCESS: Status = IOCTL::UnprotectProcess( Irp, Stack );  break;
    case IOCTL_QUERY_PROTECTION:  Status = IOCTL::QueryProtection( Irp, Stack );   break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Status;
}
