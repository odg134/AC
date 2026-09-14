#pragma once
#include <ntddk.h>

namespace Process::Guard::Integrity
{
    // Call after ObRegisterCallbacks succeeds to locate and cache our entry.
    void Bind( POB_PRE_OPERATION_CALLBACK PreOp );

    // Periodic check — returns false if tampering is detected.
    bool Validate();
}
