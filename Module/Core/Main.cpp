#include <Misc/Incl.h>

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    // Initialize the module...
    //

    printf( "Hello, world!\n" );

    return TRUE;
}
