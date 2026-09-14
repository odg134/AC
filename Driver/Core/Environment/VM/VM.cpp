#include <Misc/Incl.h>
#include <Core/Environment/VM/VM.h>
#include <Core/Environment/VM/Checks/Timing.h>
#include <Core/Environment/VM/Checks/Signature.h>
#include <Core/Environment/VM/Checks/AntiSpoof.h>

namespace VM
{
    /// <summary>
    /// Runs the full hypervisor/Hyper-V detection stack.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Check( )
    {
        if ( !Timing::ConfirmsHypervisor( ) && !Signature::HvBitPresent( ) )
            return STATUS_SUCCESS;

        if ( !Signature::IsHyperV( ) )
        {
            LogWarn( "VM: unrecognised hypervisor" );
            return STATUS_UNSUCCESSFUL;
        }

        ULONG Score = AntiSpoof::ComputeScore( );
        LogTrace( "VM: anti-spoof score {}", Score );

        if ( Score < 4 )
        {
            LogWarn( "VM: spoofed Hyper-V (score {})", Score );
            return STATUS_UNSUCCESSFUL;
        }

        Log( "VM: genuine Hyper-V (score {})", Score );
        return STATUS_SUCCESS;
    }
}
