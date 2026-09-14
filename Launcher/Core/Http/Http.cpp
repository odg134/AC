#include <Misc/Incl.h>
#include "Http.h"

namespace Http
{
    static constexpr DWORD ChunkSize = 8192;

    bool GetModule( const wchar_t* Host, INTERNET_PORT Port,
                    const wchar_t* Token, std::vector<BYTE>& OutData,
                    ProgressFn Progress )
    {
        HINTERNET Session = WinHttpOpen( L"AC-Launcher/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        if ( !Session )
            return false;

        HINTERNET Connect = WinHttpConnect( Session, Host, Port, 0 );
        if ( !Connect )
        {
            WinHttpCloseHandle( Session );
            return false;
        }

        HINTERNET Request = WinHttpOpenRequest( Connect, L"GET", L"/module",
            nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE );
        if ( !Request )
        {
            WinHttpCloseHandle( Connect );
            WinHttpCloseHandle( Session );
            return false;
        }

        //skip TLS cert validation
        //
        DWORD SecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA     |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption( Request, WINHTTP_OPTION_SECURITY_FLAGS, &SecFlags, sizeof( SecFlags ) );

        wchar_t Auth[2048];
        _snwprintf_s( Auth, _countof( Auth ), _TRUNCATE, L"Authorization: Bearer %s", Token );

        if ( !WinHttpSendRequest( Request, Auth, static_cast< DWORD >( wcslen( Auth ) ),
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ||
             !WinHttpReceiveResponse( Request, nullptr ) )
        {
            WinHttpCloseHandle( Request );
            WinHttpCloseHandle( Connect );
            WinHttpCloseHandle( Session );
            return false;
        }

        // Read Content-Length to drive progress updates
        //
        DWORD Total  = 0;
        DWORD BufLen = sizeof( DWORD );
        WinHttpQueryHeaders( Request,
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &Total, &BufLen, WINHTTP_NO_HEADER_INDEX );

        DWORD Received = 0;
        BYTE  Buf[ ChunkSize ];
        DWORD Read = 0;

        while ( WinHttpReadData( Request, Buf, ChunkSize, &Read ) && Read > 0 )
        {
            OutData.insert( OutData.end( ), Buf, Buf + Read );
            Received += Read;

            if ( Progress && Total > 0 )
                Progress( Received, Total );
        }

        WinHttpCloseHandle( Request );
        WinHttpCloseHandle( Connect );
        WinHttpCloseHandle( Session );

        return !OutData.empty( );
    }
}
