#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace Process::Telemetry
{
    static constexpr ULONG MaxEvents = 8;

#pragma pack(push, 1)
    struct AccessEvent
    {
        ULONG64  Timestamp;
        ULONG    CallerPid;
        UCHAR    CallerImageName[16];
        UCHAR    CallerProtectionByte;
        BOOLEAN  CallerIsWow64;
        BOOLEAN  CallerPebNull;
        BOOLEAN  KernelHandle;
        UCHAR    Pad;
        ACCESS_MASK RequestedAccess;
        ACCESS_MASK StrippedAccess;
    };

    struct ProcPayload
    {
        ULONG       ProtectedPid;
        ULONG       EventCount;
        AccessEvent Events[MaxEvents];
    };
#pragma pack(pop)

    static_assert( sizeof( ProcPayload ) <= Packet::MaxPayload, "ProcPayload exceeds MaxPayload" );

    Packet::Raw Build( ULONG ProtectedPid, const AccessEvent* Events, ULONG Count );
}
