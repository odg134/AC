#pragma once
#include <ntddk.h>

namespace Offsets
{
    inline UINT64 PsIntegrityCheckEnabled{};
    inline UINT64 MaxDataSize{};
    inline UINT64 Timer{};
    inline UINT64 CallbackHealthFlag{};
    inline UINT64 KiInitData{};

    NTSTATUS Init( );
}
