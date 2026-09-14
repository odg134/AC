#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include "Nic.h"

namespace Nic
{

    // Net adapter class key path.
    //
    static constexpr wchar_t ClassKeyPath[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4d36e972-e325-11ce-bfc1-08002be10318}";

    static constexpr ULONG ValueBufSize = 512;

    static NTSTATUS OpenKey( const wchar_t* Path, HANDLE* OutKey )
    {
        UNICODE_STRING Name;
        RtlInitUnicodeString( &Name, Path );

        OBJECT_ATTRIBUTES Attr{};
        InitializeObjectAttributes( &Attr, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

        return ZwOpenKey( OutKey, KEY_READ, &Attr );
    }

    // Opens a sub-key of Parent by zero-based Index.
    //
    static NTSTATUS OpenSubKeyByIndex( HANDLE Parent, ULONG Index, HANDLE* OutKey )
    {
        static constexpr ULONG InfoSize = sizeof( KEY_BASIC_INFORMATION ) + 64 * sizeof( WCHAR );
        UCHAR InfoBuf[InfoSize]{};
        auto* Info = reinterpret_cast< KEY_BASIC_INFORMATION* >( InfoBuf );

        ULONG Needed = 0;
        NTSTATUS Status = ZwEnumerateKey( Parent, Index, KeyBasicInformation, Info, InfoSize, &Needed );
        if ( !NT_SUCCESS( Status ) )
            return Status;

        UNICODE_STRING SubName{ static_cast< USHORT >( Info->NameLength ),
                                static_cast< USHORT >( Info->NameLength ),
                                Info->Name };

        OBJECT_ATTRIBUTES Attr{};
        InitializeObjectAttributes( &Attr, &SubName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, Parent, nullptr );

        return ZwOpenKey( OutKey, KEY_READ, &Attr );
    }

    // Reads a REG_SZ value from Key into Out (WCHAR buffer, OutLen = char count excl. NUL).
    //
    static bool ReadStringValue(
        HANDLE Key,
        const wchar_t* ValueName,
        WCHAR* Out,
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

        if ( Info->Type != REG_SZ || Info->DataLength < 2 )
            return false;

        auto* Src  = reinterpret_cast< const WCHAR* >( Info->Data );
        ULONG Len  = ( Info->DataLength / sizeof( WCHAR ) ) - 1; // strip NUL

        if ( Len >= OutMax )
            Len = OutMax - 1;

        RtlCopyMemory( Out, Src, Len * sizeof( WCHAR ) );
        Out[Len] = L'\0';

        if ( OutLen ) *OutLen = Len;
        return true;
    }

    /// <summary>
    /// Enumerates network adapters from the registry class key and collects
    /// hardware IDs and instance GUIDs for each adapter.
    /// </summary>
    ULONG Enumerate( NicEntry* Out, ULONG Max )
    {
        HANDLE ClassKey = nullptr;
        if ( !NT_SUCCESS( OpenKey( ClassKeyPath, &ClassKey ) ) )
        {
            LogWarn( "Nic: failed to open class key" );
            return 0;
        }

        ULONG Count = 0;

        for ( ULONG i = 0; Count < Max; ++i )
        {
            HANDLE SubKey = nullptr;
            NTSTATUS Status = OpenSubKeyByIndex( ClassKey, i, &SubKey );

            if ( Status == STATUS_NO_MORE_ENTRIES )
                break;

            if ( !NT_SUCCESS( Status ) )
                continue;

            NicEntry Entry{};

            // Skip subkeys that have no NetCfgInstanceId (not an adapter instance).
            //
            if ( !ReadStringValue( SubKey, L"NetCfgInstanceId",
                                   Entry.InstanceGuid, MaxGuidBytes, &Entry.GuidLen ) )
            {
                ZwClose( SubKey );
                continue;
            }

            // MatchingDeviceId is more reliable than HardwareID for a single string.
            //
            if ( !ReadStringValue( SubKey, L"MatchingDeviceId",
                                   Entry.HardwareId, MaxHwIdBytes, &Entry.HardwareIdLen ) )
            {
                // Fall back to ComponentId if MatchingDeviceId is absent.
                ReadStringValue( SubKey, L"ComponentId",
                                 Entry.HardwareId, MaxHwIdBytes, &Entry.HardwareIdLen );
            }

            Entry.Valid    = true;
            Out[Count++] = Entry;

            Log( "Nic: adapter {} GUID len {}", Count - 1, Entry.GuidLen );

            ZwClose( SubKey );
        }

        ZwClose( ClassKey );

        Log( "Nic: {} adapter(s) enumerated", Count );
        return Count;
    }

}
