#include <Misc/Incl.h>
#include <Core/Dispatch/Dispatch.h>

/// <summary>
/// Create the dispatch.
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
/// Close the dispatch.
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

NTSTATUS DispatchControl( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
    UNREFERENCED_PARAMETER( DeviceObject );

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation( Irp );
    ULONG              Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS           Status = STATUS_INVALID_DEVICE_REQUEST;

    switch ( Code )
    {
    case IOCTL_AC_TEST:
        Status = STATUS_SUCCESS;
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Status;
}
