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
    /// Returns true when the vendor string from CPUID(0x40000000) equals "Microsoft Hv".
    /// </summary>
    /// <returns></returns>
    bool VendorIsHyperV( )
    {
        int Info[4];
        __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafVendor ) );

        char Vendor[13] = {};
        RtlCopyMemory( Vendor + 0, &Info[1], 4 );
        RtlCopyMemory( Vendor + 4, &Info[2], 4 );
        RtlCopyMemory( Vendor + 8, &Info[3], 4 );

        return RtlEqualMemory( Vendor, "Microsoft Hv", 12 );
    }

    /// <summary>
    /// Returns true when CPUID(0x40000001).EAX equals the Hyper-V interface ID
    /// and is not the sentinel value ntoskrnl uses to suppress HV detection.
    /// </summary>
    /// <returns></returns>
    bool IsHyperV( )
    {
        if ( !VendorIsHyperV( ) )
            return false;

        int Info[4];
        __cpuid( Info, static_cast< int >( Hypercall::CpuidLeafInterface ) );
        ULONG Eax = static_cast< ULONG >( Info[0] );

        // 0x766E6258: ntoskrnl treats this as "no hypervisor present" even when the HV bit is set.
        //
        return Eax == Hypercall::InterfaceHyperV && Eax != Hypercall::InterfaceSentinel;
    }
}
