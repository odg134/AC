#include <Misc/Incl.h>
#include <Core/Offsets/Offsets.h>
#include <Core/Dispatch/Packet/Queue/Queue.h>
#include <Core/Dispatch/Packet/Crypto/Crypto.h>
#include <Core/Vectors/PPL/Telemetry/PplTelemetry.h>
#include "PPL.h"

typedef enum _SYSTEM_INFORMATION_CLASS SYSTEM_INFORMATION_CLASS;
extern "C" NTSTATUS ZwQuerySystemInformation( SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG );
extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId( HANDLE ProcessId, PEPROCESS* Process );
extern "C" NTKERNELAPI PUCHAR   PsGetProcessImageFileName( PEPROCESS Process );

namespace PPL
{
    // Processes that are legitimately PPL-protected on a normal Windows install.
    //
    static const char* const KnownProtectedImages[] = {
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "lsass.exe",
        "services.exe",
        "svchost.exe",
        "MsMpEng.exe",
        "NisSrv.exe",
        "SecurityHealthService.exe",
        "sppsvc.exe",
    };

    static bool IsKnownProtected( const char* ImageName )
    {
        for ( auto* Known : KnownProtectedImages )
        {
            const char* A = ImageName;
            const char* B = Known;
            while ( *A && *B && ( *A | 0x20 ) == ( *B | 0x20 ) )
            {
                ++A; ++B;
            }
            if ( *A == '\0' && *B == '\0' )
                return true;
        }
        return false;
    }

    // SYSTEM_PROCESS_INFORMATION subset — enough to get PID + ImageName.
    //
    struct SystemProcessInfo
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        UCHAR Reserved1[48];
        UNICODE_STRING ImageName;
        LONG  BasePriority;
        HANDLE UniqueProcessId;
        UCHAR Reserved2[160];
    };

    static constexpr ULONG SystemProcessInformation = 5;

    NTSTATUS Init()
    {
        Log( "PPL: initialized" );
        return STATUS_SUCCESS;
    }

    void Shutdown()
    {
        Log( "PPL: shutdown" );
    }

    void Snapshot( ULONG GamePid )
    {
        if ( !Offsets::EprocessProtectionOffset )
            return;

        // Query the full process list from the kernel.
        //
        ULONG BufSize = 256 * 1024;
        PVOID Buf = ExAllocatePool2( POOL_FLAG_NON_PAGED, BufSize, 'LPCA' );
        if ( !Buf )
            return;

        ULONG Returned = 0;
        NTSTATUS Status = ZwQuerySystemInformation(
            static_cast< SYSTEM_INFORMATION_CLASS >( SystemProcessInformation ),
            Buf, BufSize, &Returned );

        if ( !NT_SUCCESS( Status ) )
        {
            ExFreePool( Buf );
            return;
        }

        Telemetry::SnapEntry Entries[Telemetry::MaxEntries]{};
        ULONG Count = 0;

        auto* Info = static_cast< SystemProcessInfo* >( Buf );

        while ( true )
        {
            ULONG Pid = static_cast< ULONG >(
                reinterpret_cast< ULONG_PTR >( Info->UniqueProcessId ) );

            if ( Pid == 0 )
                goto Next;

            {
                PEPROCESS Proc{};
                if ( NT_SUCCESS( PsLookupProcessByProcessId(
                    reinterpret_cast< HANDLE >( static_cast< ULONG_PTR >( Pid ) ), &Proc ) ) )
                {
                    UCHAR ProtByte{};
                    __try
                    {
                        ProtByte = *( reinterpret_cast< PUCHAR >( Proc ) + Offsets::EprocessProtectionOffset );
                    }
                    __except ( EXCEPTION_EXECUTE_HANDLER ) {}

                    // PS_PROTECTION: bits [2:0] = Type, bits [7:3] = Signer.
                    // Type == 0 means not protected at all.
                    //
                    UCHAR ProtType = ProtByte & 0x07;

                    if ( ProtType != 0 && Count < Telemetry::MaxEntries )
                    {
                        PUCHAR ImageName = PsGetProcessImageFileName( Proc );
                        char   NameBuf[16]{};
                        if ( ImageName )
                            RtlCopyMemory( NameBuf, ImageName, sizeof( NameBuf ) - 1 );

                        bool Anomalous = !IsKnownProtected( NameBuf );

                        if ( Anomalous )
                        {
                            auto& E = Entries[Count++];
                            E.Pid           = Pid;
                            E.ProtectionByte = ProtByte;
                            E.Anomalous      = TRUE;
                            RtlCopyMemory( E.ImageName, NameBuf, sizeof( E.ImageName ) );
                        }
                    }

                    ObDereferenceObject( Proc );
                }
            }

        Next:
            if ( !Info->NextEntryOffset )
                break;
            Info = reinterpret_cast< SystemProcessInfo* >(
                reinterpret_cast< PUCHAR >( Info ) + Info->NextEntryOffset );
        }

        ExFreePool( Buf );

        if ( Count )
        {
            Packet::Raw Pkt = Telemetry::Build( GamePid, Entries, Count );
            Crypto::Nonce N = Crypto::NonceFromSequence( Pkt.Hdr.Sequence );
            Crypto::Encrypt( Pkt.Payload, Pkt.Hdr.PayloadSize, Crypto::SessionKey, N );
            Packet::g_Queue.Enqueue( Pkt );
            Log( "PPL: snapshot flagged {} anomalous process(es)", Count );
        }
    }
}
