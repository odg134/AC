#pragma once
#include <ntddk.h>

namespace Hypercall
{
    static constexpr ULONG MsrGuestOsId     = 0x40000000;
    static constexpr ULONG MsrHypercallPage = 0x40000001;
    static constexpr ULONG MsrMbecProbe     = 0x40000004;  // undocumented; write/read bit 62 to probe MBEC

    static constexpr ULONG CpuidLeafVendor        = 0x40000000;
    static constexpr ULONG CpuidLeafInterface      = 0x40000001;
    static constexpr ULONG CpuidLeafVersion        = 0x40000002;
    static constexpr ULONG CpuidLeafFeatures       = 0x40000003;
    static constexpr ULONG CpuidLeafEnlightenments = 0x40000004;
    static constexpr ULONG CpuidLeafRootPartition  = 0x40000007;

    // ntoskrnl treats this value as "no hypervisor present" even when the HV bit is set.
    // Hyper-V returns it to the root partition during HVCI/VBS; never documented in any TLFS.
    //
    static constexpr ULONG InterfaceSentinel = 0x766E6258;

    static constexpr ULONG InterfaceHyperV  = 0x31237648;  // "Hv#1"

    // Undocumented IsRootPartition flag in CPUID(0x40000007).EAX bit 31.
    //
    static constexpr ULONG RootPartitionBit = 1u << 31;

    static constexpr USHORT HcMapStatisticsPage         = 0x006C;
    static constexpr USHORT HcInternalQuery             = 0x007B;  // undocumented; dispatched by sub-code
    static constexpr USHORT HcQueryExtendedCapabilities = 0x8001;

    static constexpr ULONG SubCodeTscSync       = 14;
    static constexpr ULONG SubCodeSchedulerType = 15;

    static constexpr ULONG SchedulerTypeMin = 1;
    static constexpr ULONG SchedulerTypeMax = 4;

    static constexpr USHORT HvStatusSuccess         = 0x0000;
    static constexpr USHORT HvStatusInvalidCallCode = 0x0002;

    // Bare-metal CPUID runs in ~50-400 ticks; a VM-exit adds at minimum ~1000.
    //
    static constexpr ULONG64 TimingInterceptThreshold = 1000;

    union HypercallInput
    {
        ULONG64 Value;
        struct
        {
            ULONG64 CallCode  : 16;
            ULONG64 IsFast    : 1;
            ULONG64 Reserved1 : 15;
            ULONG64 RepCount  : 12;
            ULONG64 Reserved2 : 4;
            ULONG64 RepStart  : 12;
            ULONG64 Reserved3 : 4;
        };
    };
    static_assert( sizeof( HypercallInput ) == 8 );

    union HypercallOutput
    {
        ULONG64 Value;
        struct
        {
            ULONG64 Status        : 16;
            ULONG64 Reserved1     : 16;
            ULONG64 RepsCompleted : 12;
            ULONG64 Reserved2     : 20;
        };
    };
    static_assert( sizeof( HypercallOutput ) == 8 );
}
