#pragma once
#include <windows.h>
#include <winhttp.h>
#include <vector>
#include <functional>

namespace Http
{
    using ProgressFn = std::function< void( DWORD Received, DWORD Total ) >;

    /// <summary>
    /// GETs /module from the backend over HTTPS, streaming the response body into OutData.
    /// Progress is called with (bytes_received, total_bytes) as chunks arrive.
    /// </summary>
    bool GetModule( const wchar_t* Host, INTERNET_PORT Port,
                    const wchar_t* Token, std::vector<BYTE>& OutData,
                    ProgressFn Progress = nullptr );
}
