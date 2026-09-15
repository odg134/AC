#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "SvcReg.h"

static constexpr wchar_t ServicesKey[] =
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services";

NTSTATUS SvcReg::Collect()
{
    m_Count = 0;

    UNICODE_STRING KeyStr;
    RtlInitUnicodeString( &KeyStr, ServicesKey );
    OBJECT_ATTRIBUTES KeyOa;
    InitializeObjectAttributes( &KeyOa, &KeyStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );

    HANDLE hKey;
    NTSTATUS St = ZwOpenKey( &hKey, KEY_ENUMERATE_SUB_KEYS, &KeyOa );
    if ( !NT_SUCCESS( St ) )
        return St;

    ULONG InfoSize = 0x300;
    PVOID Info     = ExAllocatePoolZero( NonPagedPool, InfoSize, 'geSR' );
    if ( !Info )
    {
        ZwClose( hKey );
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for ( ULONG Idx = 0; m_Count < MaxEntries; ++Idx )
    {
        ULONG ResultLen = 0;
        St = ZwEnumerateKey( hKey, Idx, KeyBasicInformation, Info, InfoSize, &ResultLen );

        if ( St == STATUS_NO_MORE_ENTRIES )
            break;

        if ( St == STATUS_BUFFER_OVERFLOW || St == STATUS_BUFFER_TOO_SMALL )
        {
            ExFreePoolWithTag( Info, 'geSR' );
            InfoSize = ResultLen + 0x80;
            Info     = ExAllocatePoolZero( NonPagedPool, InfoSize, 'geSR' );
            if ( !Info )
                break;
            St = ZwEnumerateKey( hKey, Idx, KeyBasicInformation, Info, InfoSize, &ResultLen );
        }

        if ( !NT_SUCCESS( St ) )
            continue;

        auto* Basic = static_cast<KEY_BASIC_INFORMATION*>( Info );
        UNICODE_STRING SubName{
            static_cast<USHORT>( Basic->NameLength ),
            static_cast<USHORT>( Basic->NameLength ),
            Basic->Name };

        OBJECT_ATTRIBUTES SubOa;
        InitializeObjectAttributes( &SubOa, &SubName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, hKey, nullptr );

        HANDLE hSub;
        if ( !NT_SUCCESS( ZwOpenKey( &hSub, KEY_QUERY_VALUE, &SubOa ) ) )
            continue;

        UNICODE_STRING TypeStr;
        RtlInitUnicodeString( &TypeStr, L"Type" );

        UCHAR TypeBuf[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( ULONG )]{};
        ULONG TypeLen = 0;
        St = ZwQueryValueKey( hSub, &TypeStr, KeyValuePartialInformation, TypeBuf, sizeof( TypeBuf ), &TypeLen );
        ZwClose( hSub );

        if ( !NT_SUCCESS( St ) )
            continue;

        auto* Kvp = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>( TypeBuf );
        if ( Kvp->Type != REG_DWORD || Kvp->DataLength != sizeof( ULONG ) )
            continue;

        ULONG Type = *reinterpret_cast<ULONG*>( Kvp->Data );
        if ( Type != 1 && Type != 2 )
            continue;

        m_Entries[m_Count].HashName      = Hash::Blake2b(
            reinterpret_cast<const UCHAR*>( SubName.Buffer ),
            SubName.Length );
        m_Entries[m_Count].TimeDateStamp = 0;
        ++m_Count;
    }

    if ( Info )
        ExFreePoolWithTag( Info, 'geSR' );
    ZwClose( hKey );
    return STATUS_SUCCESS;
}
