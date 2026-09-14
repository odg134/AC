#include <Misc/Incl.h>
#include "Driver.h"
#include "../../../Shared/IOCTL/IOCTL.h"

namespace Driver
{
    static HANDLE Device = INVALID_HANDLE_VALUE;

    bool Open( )
    {
        Device = CreateFileW( L"\\\\.\\AC_Driver",
            GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

        return Device != INVALID_HANDLE_VALUE;
    }

    bool ProtectProcess( ULONG Pid )
    {
        if ( Device == INVALID_HANDLE_VALUE )
            return false;

        IOCTL::ProtectRequest Req{ Pid };
        DWORD Returned = 0;

        return DeviceIoControl( Device,
            IOCTL_PROTECT_PROCESS,
            &Req, sizeof( Req ),
            nullptr, 0,
            &Returned, nullptr ) != FALSE;
    }

    void Close( )
    {
        if ( Device != INVALID_HANDLE_VALUE )
        {
            CloseHandle( Device );
            Device = INVALID_HANDLE_VALUE;
        }
    }
}
