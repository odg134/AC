#pragma once
#include <ntddk.h>

namespace Offsets
{
    inline UINT64  KiFilterFiberContext{};
    inline UINT64* MaxDataSize{};
    inline UINT32* CallbackHealthFlag{};
    inline UINT32* PsIntegrityCheckEnabled{};
    inline UINT64  KiInitData{};
    inline UINT64  Timer{};

    NTSTATUS Init( );
}
