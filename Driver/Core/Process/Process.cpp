#include <Misc/Incl.h>
#include <Core/Process/Guard/Guard.h>
#include <Core/Process/Guard/Integrity/Integrity.h>
#include "Process.h"

namespace Process
{
    static PVOID           g_RegHandle{};
    static volatile LONG   g_ProtectedPid{};

    ULONG GetProtectedPid()
    {
        return static_cast< ULONG >( InterlockedCompareExchange( &g_ProtectedPid, 0, 0 ) );
    }

    void SetProtectedPid( ULONG Pid )
    {
        InterlockedExchange( &g_ProtectedPid, static_cast< LONG >( Pid ) );
        Log( "Process: protecting PID {}", Pid );
    }

    void ClearProtectedPid( ULONG Pid )
    {
        InterlockedCompareExchange( &g_ProtectedPid, 0, static_cast< LONG >( Pid ) );
        Log( "Process: cleared PID {}", Pid );
    }

    NTSTATUS Init()
    {
        OB_OPERATION_REGISTRATION OpReg{};
        OpReg.ObjectType           = PsProcessType;
        OpReg.Operations           = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        OpReg.PreOperation         = Guard::PreOpCallback;
        OpReg.PostOperation        = nullptr;

        OB_CALLBACK_REGISTRATION Reg{};
        Reg.Version                = OB_FLT_REGISTRATION_VERSION;
        Reg.OperationRegistrationCount = 1;
        Reg.RegistrationContext    = nullptr;
        Reg.OperationRegistration  = &OpReg;

        UNICODE_STRING Altitude = RTL_CONSTANT_STRING( L"321337" );
        Reg.Altitude             = Altitude;

        NTSTATUS Status = ObRegisterCallbacks( &Reg, &g_RegHandle );
        if ( !NT_SUCCESS( Status ) )
        {
            LogError( "Process: ObRegisterCallbacks failed: {}", Status );
            return Status;
        }

        Guard::Integrity::Bind( Guard::PreOpCallback );

        Log( "Process: callbacks registered" );
        return STATUS_SUCCESS;
    }

    void Shutdown()
    {
        if ( g_RegHandle )
        {
            ObUnRegisterCallbacks( g_RegHandle );
            g_RegHandle = nullptr;
        }

        InterlockedExchange( &g_ProtectedPid, 0 );
        Log( "Process: callbacks unregistered" );
    }
}
