#pragma once
#include <windows.h>

namespace Driver
{
    bool Open( );
    bool ProtectProcess( ULONG Pid );
    void Close( );
}
