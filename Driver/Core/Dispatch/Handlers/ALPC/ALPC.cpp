#include <Misc/Incl.h>
#include <Core/Dispatch/Packet/Queue/Queue.h>
#include "../../../../../Shared/ALPC/ALPC.h"
#include "ALPC.h"

// Undocumented / ntifs-only types not exposed in this build's ntddk.h
//
typedef struct _PORT_MESSAGE
{
    union { struct { CSHORT DataLength; CSHORT TotalLength; } s1; ULONG Length; } u1;
    union { struct { CSHORT Type; CSHORT DataInfoOffset; } s2; ULONG ZeroInit; } u2;
    union { CLIENT_ID ClientId; double DoNotUseThisField; };
    ULONG MessageId;
    union { SIZE_T ClientViewSize; ULONG CallbackId; };
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES;

static constexpr ULONG LPC_REQUEST           = 1;
static constexpr ULONG LPC_REPLY             = 2;
static constexpr ULONG LPC_PORT_CLOSED       = 5;
static constexpr ULONG LPC_CLIENT_DIED       = 6;
static constexpr ULONG LPC_CONNECTION_REQUEST = 10;
static constexpr ULONG ALPC_MSGFLG_RELEASE_MESSAGE = 0x10000;

extern "C"
{
    NTSTATUS ZwAlpcCreatePort( PHANDLE, POBJECT_ATTRIBUTES, _ALPC_PORT_ATTRIBUTES* );
    NTSTATUS ZwAlpcAcceptConnectPort( PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES,
        _ALPC_PORT_ATTRIBUTES*, PVOID, PORT_MESSAGE*, _ALPC_MESSAGE_ATTRIBUTES*, BOOLEAN );
    NTSTATUS ZwAlpcSendWaitReceivePort( HANDLE, ULONG, PORT_MESSAGE*, _ALPC_MESSAGE_ATTRIBUTES*,
        PORT_MESSAGE*, PSIZE_T, _ALPC_MESSAGE_ATTRIBUTES*, PLARGE_INTEGER );
}

namespace ALPC
{

struct ReqMsg  { PORT_MESSAGE Hdr; RequestBody  Body; };
struct RplyMsg { PORT_MESSAGE Hdr; ReplyBody    Body; };

static HANDLE    ServerPort = nullptr;
static PKTHREAD  Thread     = nullptr;
static bool      Stopping   = false;

static void FillReply( RplyMsg* Out, PORT_MESSAGE* Req, MsgType Type, const UCHAR* Data, USHORT DataSize )
{
    RtlZeroMemory( Out, sizeof( *Out ) );
    Out->Hdr.u1.s1.DataLength  = static_cast< CSHORT >( sizeof( ReplyBody ) );
    Out->Hdr.u1.s1.TotalLength = static_cast< CSHORT >( sizeof( PORT_MESSAGE ) + sizeof( ReplyBody ) );
    Out->Hdr.u2.s2.Type        = LPC_REPLY;
    Out->Hdr.MessageId         = Req->MessageId;
    Out->Body.Type             = Type;
    Out->Body.DataSize         = DataSize;
    if ( Data && DataSize )
        RtlCopyMemory( Out->Body.Data, Data, DataSize );
}

static void HandleClient( HANDLE CommPort )
{
    LARGE_INTEGER Timeout{};
    Timeout.QuadPart = -500LL * 10'000LL;

    UCHAR RecvBuf[sizeof( ReqMsg ) + 8]{};

    while ( !Stopping )
    {
        RtlZeroMemory( RecvBuf, sizeof( RecvBuf ) );
        SIZE_T RecvLen = sizeof( RecvBuf );

        // Receive next request
        NTSTATUS S = ZwAlpcSendWaitReceivePort(
            CommPort, 0,
            nullptr, nullptr,
            reinterpret_cast<PORT_MESSAGE*>( RecvBuf ), &RecvLen,
            nullptr, &Timeout
        );

        if ( S == STATUS_TIMEOUT )
            continue;

        if ( !NT_SUCCESS( S ) )
            break;

        auto* Msg = reinterpret_cast<ReqMsg*>( RecvBuf );
        ULONG MsgType = Msg->Hdr.u2.s2.Type & 0x3FF;

        if ( MsgType == LPC_PORT_CLOSED || MsgType == LPC_CLIENT_DIED )
            break;

        if ( MsgType != LPC_REQUEST )
            continue;

        // Build and send reply (separate call)
        RplyMsg Reply{};

        if ( Msg->Body.Type == ALPC::MsgType::RequestTelemetry )
        {
            Packet::Raw Pkt{};

            if ( Packet::g_Queue.Dequeue( &Pkt ) )
                FillReply( &Reply, &Msg->Hdr, ALPC::MsgType::TelemetryData,
                    reinterpret_cast<UCHAR*>( &Pkt ), sizeof( Pkt ) );
            else
                FillReply( &Reply, &Msg->Hdr, ALPC::MsgType::Empty, nullptr, 0 );
        }
        else
        {
            FillReply( &Reply, &Msg->Hdr, ALPC::MsgType::Empty, nullptr, 0 );
        }

        ZwAlpcSendWaitReceivePort(
            CommPort, ALPC_MSGFLG_RELEASE_MESSAGE,
            &Reply.Hdr, nullptr,
            nullptr, nullptr,
            nullptr, nullptr
        );
    }
}

static void ServerThread( PVOID )
{
    Log( "ALPC: server thread started" );

    UNICODE_STRING PortName;
    RtlInitUnicodeString( &PortName, AC_ALPC_PORT_NAME );

    OBJECT_ATTRIBUTES Attr{};
    InitializeObjectAttributes( &Attr, &PortName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

    ALPC_PORT_ATTRIBUTES PortAttr{};
    PortAttr.SecurityQos.Length               = sizeof( SECURITY_QUALITY_OF_SERVICE );
    PortAttr.SecurityQos.ImpersonationLevel   = SecurityImpersonation;
    PortAttr.SecurityQos.ContextTrackingMode  = SECURITY_DYNAMIC_TRACKING;
    PortAttr.SecurityQos.EffectiveOnly        = FALSE;
    PortAttr.MaxMessageLength                 = sizeof( RplyMsg );

    NTSTATUS Status = ZwAlpcCreatePort( &ServerPort, &Attr, &PortAttr );
    if ( !NT_SUCCESS( Status ) )
    {
        LogError( "ALPC: ZwAlpcCreatePort failed: {}", Status );
        PsTerminateSystemThread( Status );
        return;
    }

    Log( "ALPC: listening on \\RPC Control\\ACPort" );

    LARGE_INTEGER Timeout{};
    Timeout.QuadPart = -500LL * 10'000LL;

    while ( !Stopping )
    {
        UCHAR ConnBuf[sizeof( ReqMsg )]{};
        SIZE_T ConnLen = sizeof( ConnBuf );

        NTSTATUS S = ZwAlpcSendWaitReceivePort(
            ServerPort, 0, nullptr, nullptr,
            reinterpret_cast<PORT_MESSAGE*>( ConnBuf ), &ConnLen,
            nullptr, &Timeout
        );

        if ( S == STATUS_TIMEOUT )
            continue;

        if ( !NT_SUCCESS( S ) )
            break;

        auto* Msg = reinterpret_cast<PORT_MESSAGE*>( ConnBuf );
        if ( ( Msg->u2.s2.Type & 0x3FF ) != LPC_CONNECTION_REQUEST )
            continue;

        // Accept the client | one at a time
        //
        HANDLE CommPort = nullptr;
        S = ZwAlpcAcceptConnectPort( &CommPort, ServerPort, 0, nullptr, nullptr, nullptr, Msg, nullptr, TRUE );

        if ( !NT_SUCCESS( S ) )
        {
            LogWarn( "ALPC: accept failed: {}", S );
            continue;
        }

        Log( "ALPC: client connected" );
        HandleClient( CommPort );
        Log( "ALPC: client disconnected" );

        ZwClose( CommPort );
    }

    Log( "ALPC: server thread exiting" );
    PsTerminateSystemThread( STATUS_SUCCESS );
}

NTSTATUS Start( )
{
    Stopping = false;

    OBJECT_ATTRIBUTES Attr{};
    InitializeObjectAttributes( &Attr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr );

    HANDLE Handle{};
    NTSTATUS Status = PsCreateSystemThread( &Handle, THREAD_ALL_ACCESS, &Attr, nullptr, nullptr, ServerThread, nullptr );

    if ( !NT_SUCCESS( Status ) )
    {
        LogError( "ALPC: PsCreateSystemThread failed: {}", Status );
        return Status;
    }

    Status = ObReferenceObjectByHandle( Handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
        reinterpret_cast<PVOID*>( &Thread ), nullptr );

    ZwClose( Handle );

    if ( NT_SUCCESS( Status ) )
        Log( "ALPC: started" );
    else
        LogError( "ALPC: ObReferenceObjectByHandle failed: {}", Status );

    return Status;
}

void Stop( )
{
    Stopping = true;

    if ( ServerPort )
    {
        ZwClose( ServerPort );
        ServerPort = nullptr;
    }

    if ( Thread )
    {
        KeWaitForSingleObject( Thread, Executive, KernelMode, FALSE, nullptr );
        ObDereferenceObject( Thread );
        Thread = nullptr;
    }

    Log( "ALPC: stopped" );
}

}
