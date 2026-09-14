#include <Misc/Incl.h>
#include <Core/Thread/Thread.h>

namespace Thread {

    static KEVENT StopEvent;
    static PKTHREAD Kthread;

    /// <summary>
    /// Worker thread function.
    /// </summary>
    /// <param name=""></param>
    static void Worker( PVOID )
    {
        LARGE_INTEGER Interval{};
        Interval.QuadPart = -100LL * 10'000LL;

        while ( true )
        {
            NTSTATUS Status = KeWaitForSingleObject( &StopEvent, Executive, KernelMode, FALSE, &Interval );

            // If the stop event is signaled, then we exit the thread...
            //
            if ( Status == STATUS_SUCCESS )
                break;
        }

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
            return Status;

        Status = ObReferenceObjectByHandle( Handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, reinterpret_cast< PVOID* >( &Kthread ), nullptr );

        ZwClose( Handle );
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
    }

}
