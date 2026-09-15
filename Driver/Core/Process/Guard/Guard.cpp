#include <Misc/Incl.h>
#include <Core/Process/Process.h>
#include <Core/Offsets/Offsets.h>
#include "Guard.h"

extern "C" NTKERNELAPI PUCHAR   PsGetProcessImageFileName( PEPROCESS Process );
extern "C" NTKERNELAPI PVOID    PsGetProcessWow64Process( PEPROCESS Process );
extern "C" NTKERNELAPI PPEB     PsGetProcessPeb( PEPROCESS Process );

namespace Process::Guard
{
    static constexpr ULONG RingCapacity = 64;

    static Telemetry::AccessEvent g_Ring[RingCapacity]{};
    static ULONG                  g_Head{};
    static ULONG                  g_Count{};
    static KSPIN_LOCK             g_Lock{};
    static bool                   g_LockInit{};

    static void EnsureLock()
    {
        if ( !g_LockInit )
        {
            KeInitializeSpinLock( &g_Lock );
            g_LockInit = true;
        }
    }

    static void PushEvent( const Telemetry::AccessEvent& Ev )
    {
        EnsureLock();

        KIRQL Irql;
        KeAcquireSpinLock( &g_Lock, &Irql );

        g_Ring[g_Head % RingCapacity] = Ev;
        ++g_Head;
        if ( g_Count < RingCapacity )
            ++g_Count;

        KeReleaseSpinLock( &g_Lock, Irql );
    }

    ULONG DrainEvents( Telemetry::AccessEvent* Out, ULONG Max )
    {
        EnsureLock();

        KIRQL Irql;
        KeAcquireSpinLock( &g_Lock, &Irql );

        ULONG Take  = g_Count < Max ? g_Count : Max;
        ULONG Start = ( g_Head - g_Count + RingCapacity ) % RingCapacity;

        for ( ULONG I = 0; I < Take; ++I )
            Out[I] = g_Ring[( Start + I ) % RingCapacity];

        g_Count = 0;
        g_Head  = 0;

        KeReleaseSpinLock( &g_Lock, Irql );
        return Take;
    }

    OB_PREOP_CALLBACK_STATUS PreOpCallback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info )
    {
        ULONG GamePid = Process::GetProtectedPid();
        if ( !GamePid )
            return OB_PREOP_SUCCESS;

        // Only intercept the protected process object.
        PEPROCESS Target = static_cast< PEPROCESS >( Info->Object );
        if ( PsGetProcessId( Target ) != reinterpret_cast< HANDLE >( static_cast< ULONG_PTR >( GamePid ) ) )
            return OB_PREOP_SUCCESS;

        // Never strip kernel-originated handles from our own driver module.
        // Let ntoskrnl and system components through without logging.
        if ( Info->KernelHandle )
        {
            PEPROCESS Caller = PsGetCurrentProcess();
            if ( Caller == PsInitialSystemProcess )
                return OB_PREOP_SUCCESS;
        }

        ACCESS_MASK Original = Info->Parameters->CreateHandleInformation.DesiredAccess;

        // Duplicate operations store desired access differently.
        if ( Info->Operation == OB_OPERATION_HANDLE_DUPLICATE )
            Original = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

        ACCESS_MASK Stripped = Original & ~StripMask;

        if ( Info->Operation == OB_OPERATION_HANDLE_CREATE )
            Info->Parameters->CreateHandleInformation.DesiredAccess = Stripped;
        else
            Info->Parameters->DuplicateHandleInformation.DesiredAccess = Stripped;

        // Build an event to report via telemetry.
        PEPROCESS Caller = PsGetCurrentProcess();

        Telemetry::AccessEvent Ev{};

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );
        Ev.Timestamp = static_cast< ULONG64 >( Now.QuadPart );

        Ev.CallerPid    = static_cast< ULONG >( reinterpret_cast< ULONG_PTR >( PsGetProcessId( Caller ) ) );
        Ev.KernelHandle = Info->KernelHandle ? TRUE : FALSE;

        PUCHAR ImageName = PsGetProcessImageFileName( Caller );
        if ( ImageName )
            RtlCopyMemory( Ev.CallerImageName, ImageName, sizeof( Ev.CallerImageName ) - 1 );

        Ev.CallerIsWow64 = PsGetProcessWow64Process( Caller ) != nullptr ? TRUE : FALSE;
        Ev.CallerPebNull = PsGetProcessPeb( Caller ) == nullptr ? TRUE : FALSE;

        Ev.RequestedAccess = Original;
        Ev.StrippedAccess  = Original & StripMask;

        // Read PS_PROTECTION byte from caller's EPROCESS if we have the offset.
        if ( Offsets::EprocessProtectionOffset )
        {
            __try
            {
                Ev.CallerProtectionByte = *( reinterpret_cast< PUCHAR >( Caller ) + Offsets::EprocessProtectionOffset );
            }
            __except ( EXCEPTION_EXECUTE_HANDLER ) {}
        }

        if ( Ev.StrippedAccess )
            PushEvent( Ev );

        return OB_PREOP_SUCCESS;
    }

}
