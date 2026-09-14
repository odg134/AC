#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "Dns.h"

namespace Dns
{

    static constexpr wchar_t TcpipParamsPath[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";

    static constexpr ULONG  ValueBufSize = 512;

    static constexpr UCHAR DnsSalt[] = {
        0x7C, 0x3A, 0xF1, 0x88, 0x02, 0xD4, 0x5B, 0xE9,
        0xA0, 0x6D, 0xC7, 0x14, 0x93, 0x2F, 0x4E, 0xB6
    };

    static NTSTATUS OpenKey( const wchar_t* Path, HANDLE* OutKey )
    {
        UNICODE_STRING Name;
        RtlInitUnicodeString( &Name, Path );

        OBJECT_ATTRIBUTES Attr{};
        InitializeObjectAttributes( &Attr, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

        return ZwOpenKey( OutKey, KEY_READ, &Attr );
    }

    // Reads a REG_SZ or REG_MULTI_SZ value and returns its first string as ANSI.
    //
    static bool ReadWstrAsAnsi(
        HANDLE Key,
        const wchar_t* ValueName,
        char* Out,
        ULONG OutMax,
        ULONG* OutLen )
    {
        UNICODE_STRING ValStr;
        RtlInitUnicodeString( &ValStr, ValueName );

        UCHAR InfoBuf[ValueBufSize]{};
        auto* Info = reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( InfoBuf );

        ULONG Needed = 0;
        NTSTATUS Status = ZwQueryValueKey( Key, &ValStr, KeyValuePartialInformation,
                                           Info, ValueBufSize, &Needed );
        if ( !NT_SUCCESS( Status ) )
            return false;

        if ( ( Info->Type != REG_SZ && Info->Type != REG_MULTI_SZ ) || Info->DataLength < 2 )
            return false;

        auto* Wide = reinterpret_cast< const WCHAR* >( Info->Data );
        ULONG WLen = Info->DataLength / sizeof( WCHAR );

        ULONG Written = 0;
        for ( ULONG i = 0; i < WLen && Written < OutMax - 1; ++i )
        {
            if ( Wide[i] == L'\0' )
                break;
            Out[Written++] = static_cast< char >( Wide[i] & 0x7F );
        }
        Out[Written] = '\0';

        if ( OutLen ) *OutLen = Written;
        return Written > 0;
    }

    static ULONG64 HashString( const char* Str, ULONG Len )
    {
        return Hash::Argon2i(
            reinterpret_cast< const UCHAR* >( Str ), Len,
            DnsSalt, sizeof( DnsSalt ),
            1, 8 );
    }

    /// <summary>
    /// Reads DNS domain suffix and hostname from the Tcpip registry parameters.
    /// </summary>
    NTSTATUS Collect( DnsInfo* Out )
    {
        *Out = {};

        HANDLE Key = nullptr;
        NTSTATUS Status = OpenKey( TcpipParamsPath, &Key );
        if ( !NT_SUCCESS( Status ) )
        {
            LogWarn( "Dns: failed to open Tcpip parameters ({})", Status );
            return Status;
        }

        char Buf[256]{};
        ULONG Len = 0;

        // Try "NV Domain" first (static setting), fall back to "Domain" (DHCP).
        //
        if ( !ReadWstrAsAnsi( Key, L"NV Domain", Buf, sizeof( Buf ), &Len ) )
            ReadWstrAsAnsi( Key, L"Domain", Buf, sizeof( Buf ), &Len );

        if ( Len > 0 )
        {
            Out->HashDomain = HashString( Buf, Len );
            Log( "Dns: domain hash -> {}", Out->HashDomain );
        }

        Len = 0;
        RtlZeroMemory( Buf, sizeof( Buf ) );
        if ( ReadWstrAsAnsi( Key, L"Hostname", Buf, sizeof( Buf ), &Len ) && Len > 0 )
        {
            Out->HashHostname = HashString( Buf, Len );
            Log( "Dns: hostname hash -> {}", Out->HashHostname );
        }

        ZwClose( Key );

        Out->Valid = Out->HashDomain != 0 || Out->HashHostname != 0;
        return Out->Valid ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

}
