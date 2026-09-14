#include <Misc/Incl.h>
#include <intrin.h>
#include <Core/Environment/VM/Checks/Signature.h>
#include <Core/Environment/VM/Hypercall/Defs.h>

namespace VM::Signature
{
    /// <summary>
    /// Returns true when CPUID leaf 1 ECX bit 31 (hypervisor-present) is set.
    /// </summary>
    /// <returns></returns>
    bool HvBitPresent( )
    {
        int Info[4];
        __cpuid( Info, 1 );
        return ( Info[2] & ( 1 << 31 ) ) != 0;
    }

    /// <summary>
    /// Returns true when the hypervisor vendor string, interface ID,
    /// and sentinel exclusion all match genuine Hyper-V.
    /// </summary>
    /// <returns></returns>
    bool IsHyperV( )
    {
        int Info[4];
        __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafVendor ) );

        char Vendor[13] = {};
        RtlCopyMemory( Vendor + 0, &Info[1], 4 );
        RtlCopyMemory( Vendor + 4, &Info[2], 4 );
        RtlCopyMemory( Vendor + 8, &Info[3], 4 );

        if ( !RtlEqualMemory( Vendor, "Microsoft Hv", 12 ) )
            return false;

        __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafInterface ) );
        ULONG Eax = static_cast< ULONG >( Info[0] );

        // 0x766E6258: ntoskrnl treats this value as "no hypervisor present" even when
        // the HV bit is set; Hyper-V returns it to its root partition during HVCI/VBS.
        //
        return Eax == Hypercall::InterfaceHyperV && Eax != Hypercall::InterfaceSentinel;
    }
}
