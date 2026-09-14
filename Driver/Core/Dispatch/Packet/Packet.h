#pragma once
#include <ntddk.h>

namespace Packet
{
    static constexpr UINT32 Magic = 0xAC010000;
    static constexpr ULONG  MaxPayload = 512;

    enum class Type : UINT16
    {
        Hwid      = 1,
        Vm        = 2,
        Regions   = 3,
        Integrity = 4,
        Drivers   = 5,
        Process   = 6,
        Ppl       = 7,
    };

#pragma pack(push, 1)
    struct Header
    {
        UINT32 Magic;
        Type   PacketType;
        UINT16 Version;
        UINT32 Sequence;
        UINT64 Timestamp;
        UINT32 PayloadSize;
    };

    struct Raw
    {
        Header Hdr;
        UCHAR  Payload[MaxPayload];
    };
#pragma pack(pop)

    inline LONG g_Sequence = 0;
}
