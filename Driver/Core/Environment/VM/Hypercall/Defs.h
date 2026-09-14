#pragma once
#include <ntddk.h>

namespace Hypercall
{
    // MSRs used by the Hyper-V interface.
    //
    static constexpr ULONG MsrGuestOsId     = 0x40000000;
    static constexpr ULONG MsrHypercallPage = 0x40000001;
    static constexpr ULONG MsrMbecProbe     = 0x40000004;  // undocumented; write/read bit 62 to probe MBEC

    // CPUID hypervisor leaves.
    //
    static constexpr ULONG CpuidLeafVendor         = 0x40000000;
    static constexpr ULONG CpuidLeafInterface       = 0x40000001;
    static constexpr ULONG CpuidLeafVersion         = 0x40000002;
    static constexpr ULONG CpuidLeafFeatures        = 0x40000003;
    static constexpr ULONG CpuidLeafEnlightenments  = 0x40000004;
    static constexpr ULONG CpuidLeafRootPartition   = 0x40000007;

    // CPUID(0x40000001).EAX sentinel: ntoskrnl treats this as "no hypervisor present".
    // Hyper-V returns it to its root partition during HVCI/VBS initialisation.
    // Not documented in any public TLFS revision.
    //
    static constexpr ULONG InterfaceSentinel = 0x766E6258;

    // Genuine Hyper-V interface identifier ("Hv#1").
    //
    static constexpr ULONG InterfaceHyperV = 0x31237648;

    // CPUID(0x40000007).EAX bit 31: undocumented IsRootPartition flag.
    // Only genuine Hyper-V sets this; no third-party hypervisor emulator does.
    //
    static constexpr ULONG RootPartitionBit = 1u << 31;

    // Hypercall call codes.
    //
    static constexpr USHORT HcMapStatisticsPage         = 0x006C;
    static constexpr USHORT HcInternalQuery             = 0x007B;  // undocumented; dispatched by sub-code
    static constexpr USHORT HcQueryExtendedCapabilities = 0x8001;

    // Sub-codes for HcInternalQuery (0x7B), placed at input page offset 0.
    //
    static constexpr ULONG SubCodeTscSync       = 14;
    static constexpr ULONG SubCodeSchedulerType = 15;

    // Valid scheduler type values returned by sub-code 15.
    // 4 = root/SVM scheduler.
    //
    static constexpr ULONG SchedulerTypeMin = 1;
    static constexpr ULONG SchedulerTypeMax = 4;

    // HV_STATUS codes.
    //
    static constexpr USHORT HvStatusSuccess         = 0x0000;
    static constexpr USHORT HvStatusInvalidCallCode = 0x0002;

    // Minimum RDTSC ticks for a CPUID that is intercepted by a hypervisor VM-exit.
    // Bare-metal CPUID runs in ~50-400 ticks; a VM-exit adds at least ~1000.
    //
    static constexpr ULONG64 TimingInterceptThreshold = 1000;

    // Hypercall input control value layout (TLFS 3.3).
    //
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

    // Hypercall output control value layout (TLFS 3.3).
    //
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
