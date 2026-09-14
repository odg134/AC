#include <Misc/Incl.h>
#include <Core/Splash/Splash.h>
#include <Core/Http/Http.h>
#include <Core/Crypto/Crypto.h>
#include <Core/Mapper/Mapper.h>
#include <Core/Driver/Driver.h>

static constexpr wchar_t      BackendHost[] = L"localhost";
static constexpr INTERNET_PORT BackendPort   = 3000;
static constexpr wchar_t      TargetExe[]   = L"notepad.exe";

/// <summary>
/// Reads AC_TOKEN from the environment into Out. Returns false if the variable is
/// absent or the conversion fails.
/// </summary>
static bool ReadToken( wchar_t* Out, DWORD OutCch )
{
    char Narrow[2048]{};
    if ( !GetEnvironmentVariableA( "AC_TOKEN", Narrow, sizeof( Narrow ) ) )
        return false;
    return MultiByteToWideChar( CP_UTF8, 0, Narrow, -1, Out, static_cast< int >( OutCch ) ) > 0;
}

static DWORD WINAPI WorkerProc( PVOID )
{
    wchar_t Token[2048]{};
    if ( !ReadToken( Token, _countof( Token ) ) )
    {
        Splash::Quit( );
        return 1;
    }

    // Download the encrypted module payload, updating the bar from 10 → 60 %
    //
    Splash::SetProgress( 5 );

    std::vector<BYTE> Payload;
    bool Ok = Http::GetModule( BackendHost, BackendPort, Token, Payload,
        []( DWORD Recv, DWORD Total )
        {
            int Pct = 10 + static_cast< int >( 50.0 * Recv / Total );
            Splash::SetProgress( Pct );
        } );

    if ( !Ok )
    {
        Splash::Quit( );
        return 1;
    }

    Splash::SetProgress( 62 );

    // Decrypt in-place: strips 12-byte nonce prefix, XORs ciphertext with ChaCha20 keystream
    //
    if ( !Crypto::Decrypt( Payload ) )
    {
        Splash::Quit( );
        return 1;
    }

    Splash::SetProgress( 70 );

    DWORD Pid = Mapper::FindProcess( TargetExe );
    if ( !Pid )
    {
        Splash::Quit( );
        return 1;
    }

    HANDLE Process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, Pid );
    if ( !Process )
    {
        Splash::Quit( );
        return 1;
    }

    Splash::SetProgress( 75 );

    bool Mapped = Mapper::Map( Process, Payload );
    CloseHandle( Process );

    if ( !Mapped )
    {
        Splash::Quit( );
        return 1;
    }

    Splash::SetProgress( 90 );

    // Register the target PID with the driver for protection
    //
    if ( Driver::Open( ) )
    {
        Driver::ProtectProcess( Pid );
        Driver::Close( );
    }

    Splash::SetProgress( 100 );

    Sleep( 1500 );
    Splash::Quit( );
    return 0;
}

int main( )
{
    if ( !Splash::Create( ) )
        return 1;

    HANDLE Worker = CreateThread( nullptr, 0, WorkerProc, nullptr, 0, nullptr );

    Splash::Pump( );

    if ( Worker )
    {
        WaitForSingleObject( Worker, INFINITE );
        CloseHandle( Worker );
    }

    Splash::Destroy( );
    return 0;
}
