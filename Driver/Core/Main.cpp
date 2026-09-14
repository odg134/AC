#include <Misc/Incl.h>
#include <Core/Dispatch/Dispatch.h>
#include <Core/Thread/Thread.h>
#include <Core/Offsets/Offsets.h>

DRIVER_UNLOAD DriverUnload;

/// <summary>
/// The driver unload routine.
/// </summary>
/// <param name="DriverObject"></param>
void DriverUnload( PDRIVER_OBJECT DriverObject )
{
    Thread::Stop();

    UNICODE_STRING Symlink = RTL_CONSTANT_STRING( L"\\DosDevices\\AC_Driver" );
    IoDeleteSymbolicLink( &Symlink );
    IoDeleteDevice( DriverObject->DeviceObject );

    Log( "Driver unloaded" );
}

/// <summary>
/// Initialize the driver entry.
/// </summary>
/// <param name="DriverObject"></param>
/// <param name="RegistryPath"></param>
/// <returns></returns>
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
)
{
    UNREFERENCED_PARAMETER( RegistryPath );

    // Setup the driver device...
    //
    UNICODE_STRING Device = RTL_CONSTANT_STRING( L"\\Device\\AC_Driver" );
    UNICODE_STRING Symlink = RTL_CONSTANT_STRING( L"\\DosDevices\\AC_Driver" );

    PDEVICE_OBJECT DeviceObject = nullptr;
    NTSTATUS Status = IoCreateDevice( DriverObject, 0, &Device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject );

    if ( !NT_SUCCESS( Status ) )
    {
        LogError( "IoCreateDevice failed: {}", Status );
        return Status;
    }

    Status = IoCreateSymbolicLink( &Symlink, &Device );
    if ( !NT_SUCCESS( Status ) )
    {
        LogError( "IoCreateSymbolicLink failed: {}", Status );
        IoDeleteDevice( DeviceObject );
        return Status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

    Status = Offsets::Init();
    if ( !NT_SUCCESS( Status ) )
    {
        LogError( "Offsets::Init failed: {}", Status );
        IoDeleteSymbolicLink( &Symlink );
        IoDeleteDevice( DeviceObject );
        return Status;
    }

    // Setup the main worker thread...
    //
    Status = Thread::Start();
    if ( !NT_SUCCESS( Status ) )
    {
        LogError( "Thread::Start failed: {}", Status );
        IoDeleteSymbolicLink( &Symlink );
        IoDeleteDevice( DeviceObject );
        return Status;
    }

    Log( "Driver loaded" );
    return STATUS_SUCCESS;
}
