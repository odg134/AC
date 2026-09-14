#pragma once
#include <ntddk.h>

namespace Util
{
    struct DriverInfo
    {
        PVOID Base;
        ULONG Size;
    };

    bool QueryDriver( const char* Name, DriverInfo* Out );
    PVOID DriverBase( const char* Name );
    ULONG DriverSize( const char* Name );
}
