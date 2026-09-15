#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>

class Drivers;

namespace Vectors
{
#pragma pack(push, 1)
    struct DriverEntry {
        ULONG64 HashName;
        ULONG   TimeDateStamp;
        UCHAR   IsUnloaded;
    };

    static constexpr ULONG MaxDriverEntries =
        (Packet::MaxPayload - sizeof(ULONG)) / sizeof(DriverEntry);

    struct Payload {
        ULONG       DriverCount;
        DriverEntry Drivers[MaxDriverEntries];
    };
#pragma pack(pop)

    static_assert(sizeof(Payload) <= Packet::MaxPayload);

    struct Source {
        const Drivers* DriverInfo;
    };

    Packet::Raw Build(const Source& Src);
}
