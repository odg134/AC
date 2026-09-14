#include <Misc/Incl.h>
#include <Core/Environment/VM/VM.h>
#include <Core/Environment/VM/Checks/Timing.h>
#include <Core/Environment/VM/Checks/Signature.h>
#include <Core/Environment/VM/Telemetry/VmTelemetry.h>
#include <Core/Dispatch/Packet/Queue/Queue.h>

namespace VM
{
    /// <summary>
    /// Runs the full hypervisor detection stack and enqueues a telemetry packet
    /// with all raw detection values. The backend determines whether to act.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Check( )
    {
        if ( !Timing::ConfirmsHypervisor( ) && !Signature::HvBitPresent( ) )
            return STATUS_SUCCESS;

        Packet::Raw Pkt = Telemetry::Build( );

        if ( !Packet::g_Queue.Enqueue( Pkt ) )
            LogWarn( "VM: telemetry queue full" );

        return STATUS_SUCCESS;
    }
}
