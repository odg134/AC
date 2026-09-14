#include <Misc/Incl.h>
#include <Core/ALPC/ALPC.h>

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    UNREFERENCED_PARAMETER( hinstDLL );
    UNREFERENCED_PARAMETER( lpvReserved );

    switch ( fdwReason )
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls( hinstDLL );
        ALPC::Start( );
        break;

    case DLL_PROCESS_DETACH:
        ALPC::Stop( );
        break;
    }

    return TRUE;
}
