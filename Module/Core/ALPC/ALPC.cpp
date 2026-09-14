#include <Misc/Incl.h>
#include "../../../Shared/ALPC/ALPC.h"
#include "ALPC.h"

namespace ALPC
{
#pragma pack(push, 8)
    struct NT_PORT_MESSAGE
    {
        union { struct { USHORT DataLength; USHORT TotalLength; } s1; ULONG Length; } u1;
        union { struct { USHORT Type; USHORT DataInfoOffset; } s2; ULONG ZeroInit; } u2;
        union { struct { HANDLE UniqueProcess; HANDLE UniqueThread; } ClientId; double Unused; };
        ULONG MessageId;
        ULONG Reserved;
    };
#pragma pack(pop)

    struct UNICODE_STRING_NT { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };

    // ALPC connect/receive loaded from ntdll at runtime
    //
    typedef LONG( NTAPI* FnNtAlpcConnectPort )(
        PHANDLE, UNICODE_STRING_NT*, PVOID, PVOID, ULONG, PVOID,
        NT_PORT_MESSAGE*, PULONG, PVOID, PVOID, PLARGE_INTEGER );

    typedef LONG( NTAPI* FnNtAlpcSendWaitReceivePort )(
        HANDLE, ULONG, NT_PORT_MESSAGE*, PVOID,
        NT_PORT_MESSAGE*, PULONG, PVOID, PLARGE_INTEGER );

    static constexpr ULONG ALPC_MSGFLG_SYNC_REQUEST = 0x20000;

    static HANDLE   Port = nullptr;
    static HANDLE   ThreadHnd = nullptr;
    static bool     Stopping = false;

    static bool Connect( )
    {
        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        if ( !ntdll )
            return false;

        auto NtAlpcConnectPort = reinterpret_cast< FnNtAlpcConnectPort >(
            GetProcAddress( ntdll, "NtAlpcConnectPort" ) );

        if ( !NtAlpcConnectPort )
            return false;

        WCHAR PortNameBuf[] = AC_ALPC_PORT_NAME;
        UNICODE_STRING_NT PortName{ ( USHORT )( wcslen( PortNameBuf ) * 2 ),
                                    ( USHORT )( sizeof( PortNameBuf ) ),
                                    PortNameBuf };

        LONG S = NtAlpcConnectPort( &Port, &PortName, nullptr, nullptr, 0,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr );

        return S >= 0;
    }

    static void Worker( )
    {
        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        auto NtAlpcSendWaitReceivePort = reinterpret_cast< FnNtAlpcSendWaitReceivePort >(
            GetProcAddress( ntdll, "NtAlpcSendWaitReceivePort" ) );

        if ( !NtAlpcSendWaitReceivePort )
            return;

        while ( !Stopping )
        {
            // Request one telemetry packet
            //
            struct { NT_PORT_MESSAGE Hdr; RequestBody Body; } Req{};
            Req.Hdr.u1.s1.DataLength = sizeof( RequestBody );
            Req.Hdr.u1.s1.TotalLength = static_cast< USHORT >( sizeof( Req ) );
            Req.Body.Type = MsgType::RequestTelemetry;

            struct { NT_PORT_MESSAGE Hdr; ReplyBody Body; } Reply{};
            ULONG ReplyLen = sizeof( Reply );

            LONG S = NtAlpcSendWaitReceivePort(
                Port, ALPC_MSGFLG_SYNC_REQUEST,
                &Req.Hdr, nullptr,
                &Reply.Hdr, &ReplyLen,
                nullptr, nullptr
            );

            if ( S < 0 )
            {
                printf( "[ALPC] send/receive failed: 0x%08X\n", ( unsigned )S );
                break;
            }

            if ( Reply.Body.Type == MsgType::TelemetryData && Reply.Body.DataSize >= sizeof( PacketHeader ) )
            {
                // Header is unencrypted — readable directly
                //
                auto* Hdr = reinterpret_cast< PacketHeader* >( Reply.Body.Data );

                if ( Hdr->Magic == PacketMagic )
                {
                    printf( "[ALPC] telemetry seq=%u type=%u ts=%llu payloadBytes=%u\n",
                        Hdr->Sequence,
                        static_cast< unsigned >( Hdr->Type ),
                        Hdr->Timestamp,
                        Hdr->PayloadSize );
                }
            }

            Sleep( 500 );
        }
    }

    static DWORD WINAPI ThreadProc( PVOID )
    {
        if ( !Connect( ) )
        {
            printf( "[ALPC] failed to connect to \\RPC Control\\ACPort\n" );
            return 1;
        }

        printf( "[ALPC] connected\n" );
        Worker( );

        if ( Port )
        {
            CloseHandle( Port );
            Port = nullptr;
        }

        return 0;
    }

    void Start( )
    {
        Stopping = false;
        ThreadHnd = CreateThread( nullptr, 0, ThreadProc, nullptr, 0, nullptr );
    }

    void Stop( )
    {
        Stopping = true;
        if ( ThreadHnd )
        {
            WaitForSingleObject( ThreadHnd, 3000 );
            CloseHandle( ThreadHnd );
            ThreadHnd = nullptr;
        }
    }

}
