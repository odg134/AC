#include <Misc/Incl.h>
#include <Core/Dispatch/Packet/Queue/Queue.h>
#include <Core/Vectors/Regions/Pte/Pte.h>
#include <Core/Vectors/Regions/Modules/Modules.h>
#include <Core/Vectors/Regions/Scan/Walk.h>
#include <Core/Vectors/Regions/Scan/PeIntegrity.h>
#include <Core/Vectors/Regions/Telemetry/RegionsTelemetry.h>
#include "Regions.h"

namespace Regions
{
    /// <summary>
    /// Resolves the per-boot PTE base from ntoskrnl. Must be called once at driver init.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Initialize( )
    {
        NTSTATUS Status = Pte::Resolve( );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Regions: PTE base resolution failed ({})", Status );

        return Status;
    }

    /// <summary>
    /// Scans kernel memory for suspicious regions and enqueues a telemetry packet.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Scan( )
    {
        Modules::Snapshot Mods{};
        NTSTATUS Status = Modules::Capture( Mods );
        if ( !NT_SUCCESS( Status ) )
        {
            LogWarn( "Regions: module snapshot failed ({})", Status );
            return Status;
        }

        Scan::FindingBuffer Buf{};
        Walk::Execute( Mods, Buf );
        Scan::CheckPeIntegrity( Mods, Buf );

        if ( Buf.Count == 0 )
            return STATUS_SUCCESS;

        Packet::Raw Pkt = Telemetry::Build( Buf );
        Packet::g_Queue.Enqueue( Pkt );

        LogTrace( "Regions: {} finding(s) enqueued", Buf.Count );
        return STATUS_SUCCESS;
    }
}
