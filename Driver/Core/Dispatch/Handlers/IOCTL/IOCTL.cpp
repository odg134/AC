#include <Misc/Incl.h>
#include <Core/Process/Process.h>
#include "IOCTL.h"

/// <summary>
/// The IOCTL surface will mainly be used by the laucher, and it
/// will not relay any sensitive informatino such as telemetry and
/// other packets (ALPC will handle that with the module.)
/// </summary>
namespace IOCTL
{
    static constexpr ULONG Version = 0x00010000;

    static ULONG ProtectedPid{};
    static KSPIN_LOCK PidLock{};
    static bool Initialized = false;

    static void EnsureInit( )
    {
        if ( !Initialized )
        {
            KeInitializeSpinLock( &PidLock );
            Initialized = true;
        }
    }

    /// <summary>
    /// Responds with the driver version and whether a process is currently registered.
    /// </summary>
    /// <param name="Irp"></param>
    /// <param name="Stack"></param>
    /// <returns></returns>
    NTSTATUS Heartbeat( PIRP Irp, PIO_STACK_LOCATION Stack )
    {
        if ( Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof( HeartbeatResponse ) )
            return STATUS_BUFFER_TOO_SMALL;

        EnsureInit( );

        KIRQL Irql;
        KeAcquireSpinLock( &PidLock, &Irql );
        ULONG Pid = ProtectedPid;
        KeReleaseSpinLock( &PidLock, Irql );

        auto* Out = static_cast< HeartbeatResponse* >( Irp->AssociatedIrp.SystemBuffer );
        Out->Version = Version;
        Out->Protected = Pid != 0;

        Irp->IoStatus.Information = sizeof( HeartbeatResponse );
        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Registers a process PID for protection. Fails if one is already registered.
    /// </summary>
    /// <param name="Irp"></param>
    /// <param name="Stack"></param>
    /// <returns></returns>
    NTSTATUS ProtectProcess( PIRP Irp, PIO_STACK_LOCATION Stack )
    {
        if ( Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof( ProtectRequest ) )
            return STATUS_BUFFER_TOO_SMALL;

        EnsureInit( );

        auto* Req = static_cast< ProtectRequest* >( Irp->AssociatedIrp.SystemBuffer );
        if ( !Req->Pid )
            return STATUS_INVALID_PARAMETER;

        KIRQL Irql;
        KeAcquireSpinLock( &PidLock, &Irql );

        if ( ProtectedPid != 0 && ProtectedPid != Req->Pid )
        {
            KeReleaseSpinLock( &PidLock, Irql );
            LogWarn( "IOCTL: already protecting PID {}, rejected {}", ProtectedPid, Req->Pid );
            return STATUS_UNSUCCESSFUL;
        }

        ProtectedPid = Req->Pid;
        KeReleaseSpinLock( &PidLock, Irql );

        Process::SetProtectedPid( Req->Pid );

        Log( "IOCTL: protecting PID {}", Req->Pid );
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Clears the registered protected process.
    /// </summary>
    /// <param name="Irp"></param>
    /// <param name="Stack"></param>
    /// <returns></returns>
    NTSTATUS UnprotectProcess( PIRP Irp, PIO_STACK_LOCATION Stack )
    {
        if ( Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof( UnprotectRequest ) )
            return STATUS_BUFFER_TOO_SMALL;

        EnsureInit( );

        auto* Req = static_cast< UnprotectRequest* >( Irp->AssociatedIrp.SystemBuffer );

        KIRQL Irql;
        KeAcquireSpinLock( &PidLock, &Irql );

        if ( ProtectedPid != Req->Pid )
        {
            KeReleaseSpinLock( &PidLock, Irql );
            return STATUS_NOT_FOUND;
        }

        ProtectedPid = 0;
        KeReleaseSpinLock( &PidLock, Irql );

        Process::ClearProtectedPid( Req->Pid );

        Log( "IOCTL: unprotecting PID {}", Req->Pid );
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Returns whether a given PID is the currently registered protected process.
    /// </summary>
    /// <param name="Irp"></param>
    /// <param name="Stack"></param>
    /// <returns></returns>
    NTSTATUS QueryProtection( PIRP Irp, PIO_STACK_LOCATION Stack )
    {
        if ( Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof( QueryRequest ) ||
            Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof( QueryResponse ) )
            return STATUS_BUFFER_TOO_SMALL;

        EnsureInit( );

        auto* Req = static_cast< QueryRequest* >( Irp->AssociatedIrp.SystemBuffer );

        KIRQL Irql;
        KeAcquireSpinLock( &PidLock, &Irql );
        BOOLEAN Found = ( ProtectedPid != 0 && ProtectedPid == Req->Pid );
        KeReleaseSpinLock( &PidLock, Irql );

        auto* Out = static_cast< QueryResponse* >( Irp->AssociatedIrp.SystemBuffer );
        Out->Protected = Found;

        Irp->IoStatus.Information = sizeof( QueryResponse );
        return STATUS_SUCCESS;
    }

}
