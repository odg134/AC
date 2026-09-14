#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "Disk.h"
#include <Core/Identity/Disk/SMART/Smart.h>

static constexpr UCHAR SerialSalt[] = {
    0x4E, 0xA2, 0x17, 0xCB, 0x83, 0x5F, 0xD0, 0x92,
    0x3B, 0xE6, 0x71, 0x08, 0xAF, 0x4C, 0x29, 0xD5
};

/// <summary>
/// Hashes a null-terminated serial string with Argon2i.
/// </summary>
/// <param name="Serial"></param>
/// <returns></returns>
ULONG64 Disk::HashSerial( const char* Serial )
{
    ULONG Len = 0;
    while ( Serial[Len] ) ++Len;

    return Hash::Argon2i(
        reinterpret_cast< const UCHAR* >( Serial ), Len,
        SerialSalt, sizeof( SerialSalt ),
        1, 8 );
}

/// <summary>
/// Opens the device object for \Device\HarddiskN\DRN.
/// Caller must call ObDereferenceObject( FileObj ) when done.
/// </summary>
/// <param name="Index"></param>
/// <param name="FileObj"></param>
/// <param name="DevObj"></param>
/// <returns></returns>
NTSTATUS Disk::OpenDisk( ULONG Index, PFILE_OBJECT* FileObj, PDEVICE_OBJECT* DevObj )
{
    wchar_t NameBuf[64]{};
    ULONG Pos = 0;

    auto AppendWcs = [&] ( const wchar_t* Src ) { while ( *Src ) NameBuf[Pos++] = *Src++; };
    auto AppendNum = [&] ( ULONG N )
        {
            if ( N == 0 ) { NameBuf[Pos++] = L'0'; return; }
            wchar_t Tmp[10]; ULONG Len = 0;
            while ( N > 0 ) { Tmp[Len++] = L'0' + static_cast< wchar_t >( N % 10 ); N /= 10; }
            while ( Len > 0 ) NameBuf[Pos++] = Tmp[--Len];
        };

    AppendWcs( L"\\Device\\Harddisk" ); AppendNum( Index );
    AppendWcs( L"\\DR" );              AppendNum( Index );

    UNICODE_STRING Name{};
    RtlInitUnicodeString( &Name, NameBuf );

    return IoGetDeviceObjectPointer( &Name, FILE_READ_DATA, FileObj, DevObj );
}

/// <summary>
/// Enumerate all physical disks and collect serials via multiple independent methods.
/// </summary>
/// <returns></returns>
NTSTATUS Disk::Collect( )
{
    m_Count = 0;
    m_Hash = 0;

    for ( ULONG i = 0; i < MaxDisks; ++i )
    {
        PFILE_OBJECT FileObj = nullptr;
        PDEVICE_OBJECT DevObj = nullptr;

        NTSTATUS Status = OpenDisk( i, &FileObj, &DevObj );
        if ( !NT_SUCCESS( Status ) )
            break;

        Log( "Disk: opened disk {}", i );

        DiskSerial Entry{};

        UCHAR IdentifyBuf[Smart::IdentifyBufferSize]{};
        if ( NT_SUCCESS( Smart::SendIdentify( DevObj, IdentifyBuf ) ) )
        {
            char Serial[21]{};
            Smart::ExtractIdentifySerial( IdentifyBuf, Serial, sizeof( Serial ) );
            Entry.HashAta = HashSerial( Serial );
            Log( "Disk: [{}] ATA serial -> {}", i, Serial );
        }
        else
        {
            LogWarn( "Disk: [{}] ATA identify failed", i );
        }

        UCHAR StorageBuf[Smart::StorageDescriptorBufferSize]{};
        if ( NT_SUCCESS( Smart::QueryStorageDescriptor( DevObj, StorageBuf, sizeof( StorageBuf ) ) ) )
        {
            const char* StorageSerial = Smart::ExtractStorageSerial( StorageBuf, sizeof( StorageBuf ) );
            if ( StorageSerial )
            {
                Entry.HashStorage = HashSerial( StorageSerial );
                Log( "Disk: [{}] storage serial -> {}", i, StorageSerial );
            }
        }
        else
        {
            LogWarn( "Disk: [{}] storage query failed", i );
        }

        if ( Entry.HashAta && Entry.HashStorage && Entry.HashAta != Entry.HashStorage )
            LogWarn( "Disk: [{}] serial mismatch detected", i );

        Entry.Valid = true;
        m_Serials[m_Count++] = Entry;

        ObDereferenceObject( FileObj );
    }

    // Combine all hashes; rotate HashStorage so identical inputs don't cancel.
    //
    for ( ULONG i = 0; i < m_Count; ++i )
    {
        if ( !m_Serials[i].Valid )
            continue;

        m_Hash ^= m_Serials[i].HashAta;
        m_Hash ^= ( m_Serials[i].HashStorage << 13 ) | ( m_Serials[i].HashStorage >> 51 );
    }

    Log( "Disk: {} disk(s) collected", m_Count );
    return m_Count > 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/// <summary>
/// Returns a combined hash of all collected disk serials.
/// </summary>
/// <returns></returns>
ULONG64 Disk::Hash( ) const
{
    return m_Hash;
}

/// <summary>
/// Returns true if any disk reports different serials across collection methods.
/// </summary>
/// <returns></returns>
bool Disk::IsMismatch( ) const
{
    for ( ULONG i = 0; i < m_Count; ++i )
    {
        if ( !m_Serials[i].Valid )
            continue;

        if ( m_Serials[i].HashAta == 0 || m_Serials[i].HashStorage == 0 )
            continue;

        if ( m_Serials[i].HashAta != m_Serials[i].HashStorage )
            return true;
    }

    return false;
}

/// <summary>
/// Number of physical disks found during Collect().
/// </summary>
/// <returns></returns>
ULONG Disk::Count( ) const
{
    return m_Count;
}
