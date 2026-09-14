#include <Misc/Incl.h>
#include <intrin.h>
#include <Core/Environment/VM/Checks/Timing.h>
#include <Core/Environment/VM/Hypercall/Defs.h>

namespace VM::Timing
{
    /// <summary>
    /// Returns true when the minimum CPUID cycle count across several samples
    /// exceeds the bare-metal ceiling, conclusively indicating a hypervisor.
    /// </summary>
    /// <returns></returns>
    bool ConfirmsHypervisor( )
    {
        constexpr ULONG Samples = 16;
        ULONG64 Min = MAXULONG64;
        int Unused[4];

        __cpuid( Unused, 0 );

        for ( ULONG i = 0; i < Samples; ++i )
        {
            ULONG64 T1 = __rdtsc( );
            __cpuid( Unused, 1 );
            ULONG64 T2 = __rdtsc( );
            ULONG64 Delta = T2 - T1;
            if ( Delta < Min )
                Min = Delta;
        }

        return Min > Hypercall::TimingInterceptThreshold;
    }
}
