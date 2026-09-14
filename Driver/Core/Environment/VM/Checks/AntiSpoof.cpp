#include <Misc/Incl.h>
#include <intrin.h>
#include <Core/Environment/VM/Checks/AntiSpoof.h>
#include <Core/Environment/VM/Hypercall/Hypercall.h>
#include <Core/Environment/VM/Hypercall/Defs.h>

namespace VM::AntiSpoof
{
    // Layer 2: fakes commonly cap max leaf at 0x40000005 or below.
    //
    static bool LeafSevenPresent( )
    {
        int Info[4];
        __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafVendor ) );
        return static_cast< ULONG >( Info[0] ) >= Hypercall::CpuidLeafRootPartition;
    }

    // Layer 3: bit 31 of CPUID(0x40000007).EAX is an undocumented IsRootPartition flag.
    // No third-party hypervisor emulator sets this.
    //
    static bool IsRootPartition( )
    {
        int Info[4];
        __cpuidex( Info, static_cast< int >( Hypercall::CpuidLeafRootPartition ), 0 );
        return ( static_cast< ULONG >( Info[0] ) & Hypercall::RootPartitionBit ) != 0;
    }

    // Layer 4: undocumented hypercall 0x7B sub-code 15 (scheduler type query).
    // A fake returns HvStatusInvalidCallCode (0x0002); real Hyper-V returns type in [1,4].
    //
    static bool InternalQuerySucceeds( )
    {
        ULONG SubCode = Hypercall::SubCodeSchedulerType;
        ULONG Result  = 0;
        USHORT Status = 0;

        NTSTATUS S = Hypercall::Invoke(
            Hypercall::HcInternalQuery,
            &SubCode, sizeof( SubCode ),
            &Result,  sizeof( Result ),
            &Status );

        return NT_SUCCESS( S )
            && Status == Hypercall::HvStatusSuccess
            && Result >= Hypercall::SchedulerTypeMin
            && Result <= Hypercall::SchedulerTypeMax;
    }

    // Layer 5: hypercall 0x8001 (HvExtCallQueryCapabilities).
    // Real Hyper-V returns a non-zero capability bitmask; fakes return zero or fail.
    //
    static bool ExtendedCapsNonZero( )
    {
        ULONG64 Caps  = 0;
        USHORT  Status = 0;

        NTSTATUS S = Hypercall::Invoke(
            Hypercall::HcQueryExtendedCapabilities,
            nullptr, 0,
            &Caps, sizeof( Caps ),
            &Status );

        return NT_SUCCESS( S ) && Status == Hypercall::HvStatusSuccess && Caps != 0;
    }

    // Layer 6: CPUID(0x40000003).EBX bit 12 = feature bit 44, gates the MBEC MSR probe.
    // Write/read MSR 0x40000004; bit 62 of the read-back indicates MBEC hardware support.
    //
    static bool MbecBit62Set( )
    {
        int Info[4];
        __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafFeatures ) );
        if ( !( static_cast< ULONG >( Info[1] ) & ( 1u << 12 ) ) )
            return false;

        __writemsr( Hypercall::MsrMbecProbe, 1 );
        ULONG64 V = __readmsr( Hypercall::MsrMbecProbe );
        __writemsr( Hypercall::MsrMbecProbe, 0 );
        return ( V & 0x4000000000000000ULL ) != 0;
    }

    // Layer 7: hypercall 0x6C maps the hypervisor statistics page (root partition only).
    //
    static bool StatisticsPageMaps( )
    {
        ULONG   Arg    = 1;
        ULONG64 OutGpa = 0;
        USHORT  Status = 0;

        NTSTATUS S = Hypercall::Invoke(
            Hypercall::HcMapStatisticsPage,
            &Arg,    sizeof( Arg ),
            &OutGpa, sizeof( OutGpa ),
            &Status );

        return NT_SUCCESS( S ) && Status == Hypercall::HvStatusSuccess && OutGpa != 0;
    }


    /// <summary>
    /// Runs all anti-spoof layers. Layers 4 and 5 carry weight 2 each; all others weight 1.
    /// </summary>
    /// <returns></returns>
    ULONG ComputeScore( )
    {
        ULONG Score = 0;

        if ( LeafSevenPresent( ) ) Score += 1;
        if ( IsRootPartition( ) )  Score += 1;

        if ( !NT_SUCCESS( Hypercall::Initialize( ) ) )
        {
            LogWarn( "VM: hypercall init failed; skipping layers 4-7" );
            return Score;
        }

        if ( InternalQuerySucceeds( ) )  Score += 2;
        if ( ExtendedCapsNonZero( ) )    Score += 2;
        if ( MbecBit62Set( ) )           Score += 1;
        if ( StatisticsPageMaps( ) )     Score += 1;

        Hypercall::Cleanup( );
        return Score;
    }
}
