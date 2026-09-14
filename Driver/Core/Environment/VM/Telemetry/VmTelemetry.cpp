#include <Misc/Incl.h>
#include <intrin.h>
#include <Core/Environment/VM/Telemetry/VmTelemetry.h>
#include <Core/Environment/VM/Checks/Timing.h>
#include <Core/Environment/VM/Checks/Signature.h>
#include <Core/Environment/VM/Hypercall/Hypercall.h>
#include <Core/Environment/VM/Hypercall/Defs.h>

namespace VM::Telemetry
{
    /// <summary>
    /// Runs all hypervisor detection checks and returns a fully populated
    /// Packet::Raw ready to enqueue.
    /// </summary>
    /// <returns></returns>
    Packet::Raw Build( )
    {
        Packet::Raw Pkt{};
        auto* Pay = reinterpret_cast< VmPayload* >( Pkt.Payload );

        // Timing + basic CPUID.
        //
        Pay->MinCpuidTicks  = Timing::MeasureMinCycles( );
        Pay->HvBitSet       = Signature::HvBitPresent( ) ? TRUE : FALSE;
        Pay->VendorIsHyperV = Signature::VendorIsHyperV( ) ? TRUE : FALSE;

        {
            int Info[4];
            __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafInterface ) );
            ULONG Eax = static_cast< ULONG >( Info[0] );
            Pay->InterfaceId      = Eax;
            Pay->InterfaceIsHyperV = Signature::IsHyperV( ) ? TRUE : FALSE;
        }

        // CPUID(0x40000000).EAX: max hypervisor leaf.
        //
        {
            int Info[4];
            __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafVendor ) );
            Pay->MaxHvLeaf        = static_cast< ULONG >( Info[0] );
            Pay->LeafSevenPresent = ( Pay->MaxHvLeaf >= Hypercall::CpuidLeafRootPartition ) ? TRUE : FALSE;
        }

        // CPUID(0x40000007): undocumented root partition bit.
        //
        {
            int Info[4];
            __cpuidex( Info, static_cast< int >( Hypercall::CpuidLeafRootPartition ), 0 );
            Pay->CpuidLeafSevenEax = static_cast< ULONG >( Info[0] );
            Pay->RootPartitionBit  = ( Pay->CpuidLeafSevenEax & Hypercall::RootPartitionBit ) ? TRUE : FALSE;
        }

        // Hypercall-based layers; only attempt if Hyper-V signature is present.
        //
        Pay->HcInitSuccess = NT_SUCCESS( Hypercall::Initialize( ) ) ? TRUE : FALSE;

        if ( Pay->HcInitSuccess )
        {
            // 0x7B sub-code 15: internal scheduler type query.
            //
            {
                ULONG  SubCode = Hypercall::SubCodeSchedulerType;
                ULONG  Result  = 0;
                USHORT Status  = Hypercall::HvStatusInvalidCallCode;
                Hypercall::Invoke( Hypercall::HcInternalQuery,
                                   &SubCode, sizeof( SubCode ),
                                   &Result,  sizeof( Result ),
                                   &Status );
                Pay->HcInternalQueryStatus = Status;
                Pay->HcSchedulerType       = ( Status == Hypercall::HvStatusSuccess ) ? Result : 0;
            }

            // 0x8001: extended capability bitmask.
            //
            {
                ULONG64 Caps   = 0;
                USHORT  Status = Hypercall::HvStatusInvalidCallCode;
                Hypercall::Invoke( Hypercall::HcQueryExtendedCapabilities,
                                   nullptr, 0,
                                   &Caps, sizeof( Caps ),
                                   &Status );
                Pay->HcExtendedCapsStatus = Status;
                Pay->HcExtendedCaps       = ( Status == Hypercall::HvStatusSuccess ) ? Caps : 0;
            }

            // MSR 0x40000004 MBEC probe; gated on CPUID(0x40000003).EBX bit 12 (feature bit 44).
            //
            {
                int Info[4];
                __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafFeatures ) );
                bool FeatureBit = ( static_cast< ULONG >( Info[1] ) & ( 1u << 12 ) ) != 0;
                Pay->MbecFeatureBitSet = FeatureBit ? TRUE : FALSE;

                if ( FeatureBit )
                {
                    __writemsr( Hypercall::MsrMbecProbe, 1 );
                    ULONG64 V = __readmsr( Hypercall::MsrMbecProbe );
                    __writemsr( Hypercall::MsrMbecProbe, 0 );
                    Pay->MbecBit62Set = ( V & 0x4000000000000000ULL ) ? TRUE : FALSE;
                }
            }

            // 0x6C: statistics page mapping (root partition only).
            //
            {
                ULONG   Arg    = 1;
                ULONG64 OutGpa = 0;
                USHORT  Status = Hypercall::HvStatusInvalidCallCode;
                Hypercall::Invoke( Hypercall::HcMapStatisticsPage,
                                   &Arg,    sizeof( Arg ),
                                   &OutGpa, sizeof( OutGpa ),
                                   &Status );
                Pay->HcStatisticsPageStatus = Status;
                Pay->HcStatisticsPageGpa    = ( Status == Hypercall::HvStatusSuccess ) ? OutGpa : 0;
            }

            Hypercall::Cleanup( );
        }

        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise( &Now );

        Pkt.Hdr.Magic       = Packet::Magic;
        Pkt.Hdr.PacketType  = Packet::Type::Vm;
        Pkt.Hdr.Version     = 1;
        Pkt.Hdr.Sequence    = static_cast< UINT32 >( InterlockedIncrement( &Packet::g_Sequence ) );
        Pkt.Hdr.Timestamp   = static_cast< UINT64 >( Now.QuadPart );
        Pkt.Hdr.PayloadSize = sizeof( VmPayload );

        return Pkt;
    }
}
