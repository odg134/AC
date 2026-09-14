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
    // Require the driver to already be loaded — we never load it automatically
    //
    if ( !Driver::Open( ) )
    {
        Splash::SetError( L"Failure loading AC driver" );
        return 1;
    }

    wchar_t Token[2048]{};
    if ( !ReadToken( Token, _countof( Token ) ) )
    {
        Driver::Close( );
        Splash::SetError( L"AC_TOKEN environment variable not set" );
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
        Driver::Close( );
        Splash::SetError( L"Could not reach backend, check that it is running" );
        return 1;
    }

    Splash::SetProgress( 62 );

    // Decrypt in-place: strips 12-byte nonce prefix, XORs ciphertext with ChaCha20 keystream
    //
    if ( !Crypto::Decrypt( Payload ) )
    {
        Driver::Close( );
        Splash::SetError( L"Module decryption failed" );
        return 1;
    }

    Splash::SetProgress( 70 );

    DWORD Pid = Mapper::FindProcess( TargetExe );
    if ( !Pid )
    {
        Driver::Close( );
        Splash::SetError( L"notepad.exe is not running" );
        return 1;
    }

    HANDLE Process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, Pid );
    if ( !Process )
    {
        Driver::Close( );
        Splash::SetError( L"Could not open target process, try running as administrator" );
        return 1;
    }

    Splash::SetProgress( 75 );

    bool Mapped = Mapper::Map( Process, Payload );
    CloseHandle( Process );

    if ( !Mapped )
    {
        Driver::Close( );
        Splash::SetError( L"Module injection failed" );
        return 1;
    }

    Splash::SetProgress( 90 );

    Driver::ProtectProcess( Pid );
    Driver::Close( );

    Splash::SetProgress( 100 );
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
