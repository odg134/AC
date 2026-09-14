#pragma once
#include <windows.h>

namespace Splash
{
    bool Create( );
    void SetProgress( int Percent );
    void SetError( const wchar_t* Msg );
    void Quit( );
    void Pump( );
    void Destroy( );
}
