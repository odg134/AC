#pragma once

#ifdef _KERNEL_MODE
#  include <ntddk.h>
#else
#  include <windows.h>
#endif

#define AC_ALPC_PORT_NAME L"\\RPC Control\\ACPort"

namespace ALPC
{
    // Max bytes the server sends back for one telemetry packet.
    // Must be >= sizeof(Packet::Header) + Packet::MaxPayload (536 bytes).
    //
    static constexpr USHORT MaxData = 560;

    // Unencrypted wire header — readable without the session key.
    //
    enum class PacketType : UINT16 { Hwid = 1 };

    #pragma pack(push, 1)
    struct PacketHeader
    {
        UINT32     Magic;
        PacketType Type;
        UINT16     Version;
        UINT32     Sequence;
        UINT64     Timestamp;
        UINT32     PayloadSize;
    };
    #pragma pack(pop)

    static constexpr UINT32 PacketMagic = 0xAC010000;

    enum class MsgType : USHORT
    {
        RequestTelemetry = 1,
        TelemetryData    = 2,
        Empty            = 3,
    };

    #pragma pack(push, 1)
    struct RequestBody { MsgType Type; };
    struct ReplyBody   { MsgType Type; USHORT DataSize; UCHAR Data[MaxData]; };
    #pragma pack(pop)
}
