#include <Misc/Incl.h>
#include <Core/Thread/Thread.h>
#include <Core/Environment/Environment.h>
#include <Core/Vectors/Regions/Regions.h>
#include <Core/Identity/Identity.h>
#include <Core/Identity/Disk/Disk.h>
#include <Core/Identity/Network/Network.h>
#include <Core/Dispatch/Packet/Telemetry/Telemetry.h>
#include <Core/Dispatch/Packet/Queue/Queue.h>
#include <Core/Dispatch/Packet/Crypto/Crypto.h>
#include <Core/Process/Process.h>
#include <Core/Process/Guard/Guard.h>
#include <Core/Process/Guard/Integrity/Integrity.h>
#include <Core/Process/Telemetry/ProcTelemetry.h>
#include <Core/Vectors/PPL/PPL.h>

namespace Thread
{
    static KEVENT   StopEvent;
    static PKTHREAD Kthread;

    static Identity HwidTable;
    static Disk     DiskCollector;
    static Network  NetworkCollector;

    static constexpr ULONG CheckEvery        = 50;   // 5s  (env + integrity checks)
    static constexpr ULONG CollectEvery      = 300;  // 30s (hwid + telemetry)
    static constexpr ULONG PplSnapshotEvery  = 100;  // 10s (PPL anomaly scan)
    static constexpr ULONG ProcDrainEvery    = 20;   // 2s  (process access events)

    static void Collect( )
    {
        if ( !NT_SUCCESS( DiskCollector.Collect( ) ) )
            return;

        ULONG64 Hash = DiskCollector.Hash( );
        if ( Hash && !HwidTable.Contains( Hash ) )
            HwidTable.Add( Hash );

        NetworkCollector.Collect( );

        ULONG64 NetHash = NetworkCollector.Hash( );
        if ( NetHash && !HwidTable.Contains( NetHash ) )
            HwidTable.Add( NetHash );

        Telemetry::Source Src{ &HwidTable, &DiskCollector, nullptr, &NetworkCollector };
        Packet::Raw Pkt = Telemetry::Build( Src );

        // Encrypt payload before the packet enters the queue
        //
        Crypto::Nonce N = Crypto::NonceFromSequence( Pkt.Hdr.Sequence );
        Crypto::Encrypt( Pkt.Payload, Pkt.Hdr.PayloadSize, Crypto::SessionKey, N );

        Packet::g_Queue.Enqueue( Pkt );
        Log( "Thread: telemetry enqueued (seq {})", Pkt.Hdr.Sequence );
    }

    /// <summary>
    /// Worker thread function.
    /// </summary>
    /// <param name=""></param>
    static void Worker( PVOID )
    {
        Log( "Thread: worker started" );

        LARGE_INTEGER Interval{};
        Interval.QuadPart = -100LL * 10'000LL;

        ULONG Ticks = 0;

        while ( true )
        {
            NTSTATUS Status = KeWaitForSingleObject( &StopEvent, Executive, KernelMode, FALSE, &Interval );

            if ( Status == STATUS_SUCCESS )
                break;

            ++Ticks;

            if ( Ticks % CheckEvery == 0 )
            {
                Environment::Check( );
                Regions::Scan( );
            }

            if ( Ticks % CollectEvery == 0 )
                Collect( );
        }

        Log( "Thread: worker exiting" );
        PsTerminateSystemThread( STATUS_SUCCESS );
    }

    /// <summary>
    /// Start the worker thread.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Start( )
    {
        KeInitializeEvent( &StopEvent, SynchronizationEvent, FALSE );

        OBJECT_ATTRIBUTES Attr{};
        InitializeObjectAttributes( &Attr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr );

        // Create the system thread...
        //
        HANDLE Handle{};
        NTSTATUS Status = PsCreateSystemThread( &Handle, THREAD_ALL_ACCESS, &Attr, nullptr, nullptr, Worker, nullptr );

        if ( !NT_SUCCESS( Status ) )
        {
            LogError( "Thread: PsCreateSystemThread failed: {}", Status );
            return Status;
        }

        Status = ObReferenceObjectByHandle( Handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, reinterpret_cast< PVOID* >( &Kthread ), nullptr );

        ZwClose( Handle );

        if ( NT_SUCCESS( Status ) )
            Log( "Thread: started" );
        else
            LogError( "Thread: ObReferenceObjectByHandle failed: {}", Status );

        return Status;
    }

    /// <summary>
    /// Stop the worker thread.
    /// </summary>
    void Stop( )
    {
        KeSetEvent( &StopEvent, IO_NO_INCREMENT, FALSE );
        KeWaitForSingleObject( Kthread, Executive, KernelMode, FALSE, nullptr );
        ObDereferenceObject( Kthread );
        Kthread = nullptr;

        Log( "Thread: stopped" );
    }

}
