#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace VM::Telemetry
{
#pragma pack(push, 1)
    struct VmPayload
    {
        ULONG64 MinCpuidTicks;          // raw minimum sample; ~50-400 = bare metal

        BOOLEAN HvBitSet;               // CPUID(1).ECX bit 31
        BOOLEAN VendorIsHyperV;         // vendor string == "Microsoft Hv"
        BOOLEAN InterfaceIsHyperV;      // EAX == 0x31237648 and not the sentinel
        ULONG   InterfaceId;            // raw CPUID(0x40000001).EAX

        BOOLEAN LeafSevenPresent;       // max hypervisor leaf >= 0x40000007
        ULONG   MaxHvLeaf;              // raw CPUID(0x40000000).EAX
        BOOLEAN RootPartitionBit;       // CPUID(0x40000007).EAX bit 31 (undocumented)
        ULONG   CpuidLeafSevenEax;      // raw CPUID(0x40000007).EAX

        BOOLEAN HcInitSuccess;

        USHORT  HcInternalQueryStatus;  // raw HV_STATUS from 0x7B/sub-15
        ULONG   HcSchedulerType;        // scheduler type in [1,4], 0 on failure

        USHORT  HcExtendedCapsStatus;   // raw HV_STATUS from 0x8001
        ULONG64 HcExtendedCaps;         // raw capability bitmask

        BOOLEAN MbecFeatureBitSet;      // CPUID(0x40000003).EBX bit 12 (feature bit 44)
        BOOLEAN MbecBit62Set;           // MSR 0x40000004 read-back bit 62

        USHORT  HcStatisticsPageStatus; // raw HV_STATUS from 0x6C
        ULONG64 HcStatisticsPageGpa;    // mapped GPA, 0 on failure
    };
#pragma pack(pop)

    static_assert( sizeof( VmPayload ) <= Packet::MaxPayload, "VmPayload exceeds MaxPayload" );

    /// <summary>
    /// Runs all hypervisor detection checks and returns a fully populated
    /// Packet::Raw ready to enqueue. All fields are populated regardless of
    /// whether a hypervisor is detected; the backend makes the determination.
    /// </summary>
    /// <returns></returns>
    Packet::Raw Build( );
}
