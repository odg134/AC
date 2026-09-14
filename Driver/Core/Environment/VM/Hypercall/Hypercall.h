#pragma once
#include <ntddk.h>
#include <Core/Environment/VM/Hypercall/Defs.h>

namespace Hypercall
{
    /// <summary>
    /// Allocates the input/output transfer pages and maps the hypercall page
    /// by writing MSR 0x40000001. The previous MSR value is saved and restored
    /// by Cleanup(). Call only after confirming Hyper-V CPUID signature is present.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Initialize( );

    /// <summary>
    /// Restores MSR 0x40000001 to its original value and frees all
    /// memory allocated by Initialize().
    /// </summary>
    void Cleanup( );

    /// <summary>
    /// Issues a memory-based (non-fast) hypercall.
    /// Copies Input into the input transfer page, invokes the hypercall page stub,
    /// then copies the output transfer page into Output on success.
    /// </summary>
    /// <param name="Code">Hypercall call code (e.g. HcInternalQuery).</param>
    /// <param name="Input">Optional pointer to the input payload.</param>
    /// <param name="InputSize">Byte length of Input (must be <= PAGE_SIZE).</param>
    /// <param name="Output">Optional pointer to receive output data.</param>
    /// <param name="OutputSize">Byte capacity of Output (must be <= PAGE_SIZE).</param>
    /// <param name="HvStatus">If non-null, receives the raw HV_STATUS on return.</param>
    /// <returns></returns>
    NTSTATUS Invoke( USHORT      Code,
                     const void* Input,
                     ULONG       InputSize,
                     void*       Output,
                     ULONG       OutputSize,
                     USHORT*     HvStatus = nullptr );
}
