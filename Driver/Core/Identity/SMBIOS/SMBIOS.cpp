#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include <Core/Identity/SMBIOS/Parser/Parser.h>
#include <Core/Identity/SMBIOS/Tables/Tables.h>
#include "SMBIOS.h"

static constexpr UCHAR SmbiosSalt[] = {
    0xC3, 0x7F, 0x2A, 0x91, 0x4E, 0xB8, 0x56, 0x0D,
    0xA2, 0x3C, 0x88, 0xF4, 0x17, 0x6B, 0xE9, 0x52
};

ULONG64 Smbios::HashString( const char* Str )
{
    if ( Tables::IsJunk( Str ) )
        return 0;

    ULONG Len = 0;
    while ( Str[Len] ) ++Len;

    return Hash::Argon2i(
        reinterpret_cast< const UCHAR* >( Str ), Len,
        SmbiosSalt, sizeof( SmbiosSalt ),
        1, 8 );
}

ULONG64 Smbios::HashBytes( const UCHAR* Bytes, ULONG Len )
{
    return Hash::Blake2b( Bytes, Len );
}

NTSTATUS Smbios::Collect( )
{
    m_Hash       = 0;
    m_FieldHashes = {};

    SmbiosParser::Table T{};
    NTSTATUS Status = SmbiosParser::ReadTable( &T );
    if ( !NT_SUCCESS( Status ) )
        return Status;

    Bios::Collect(       T.Data, T.Length, &m_Bios );
    System::Collect(     T.Data, T.Length, &m_System );
    Baseboard::Collect(  T.Data, T.Length, &m_Baseboard );
    Chassis::Collect(    T.Data, T.Length, &m_Chassis );
    Processor::Collect(  T.Data, T.Length, &m_Processor );
    Memory::Collect(     T.Data, T.Length, &m_Memory );

    SmbiosParser::FreeTable( &T );

    if ( m_System.Valid )
    {
        ULONG64 UuidHash = HashBytes( m_System.UUID, 16 );
        if ( UuidHash )
        {
            m_Hash ^= UuidHash;
            Log( "SMBIOS: UUID hash -> {}", UuidHash );
        }

        m_FieldHashes.SystemSerial = HashString( m_System.SerialNumber );
        if ( m_FieldHashes.SystemSerial )
        {
            m_Hash ^= ( m_FieldHashes.SystemSerial << 7 ) | ( m_FieldHashes.SystemSerial >> 57 );
            Log( "SMBIOS: system serial hash -> {}", m_FieldHashes.SystemSerial );
        }
    }

    if ( m_Baseboard.Valid )
    {
        m_FieldHashes.BaseboardSerial = HashString( m_Baseboard.SerialNumber );
        if ( m_FieldHashes.BaseboardSerial )
        {
            m_Hash ^= ( m_FieldHashes.BaseboardSerial << 13 ) | ( m_FieldHashes.BaseboardSerial >> 51 );
            Log( "SMBIOS: baseboard serial hash -> {}", m_FieldHashes.BaseboardSerial );
        }
    }

    if ( m_Chassis.Valid )
    {
        m_FieldHashes.ChassisSerial = HashString( m_Chassis.SerialNumber );
        if ( m_FieldHashes.ChassisSerial )
        {
            m_Hash ^= ( m_FieldHashes.ChassisSerial << 19 ) | ( m_FieldHashes.ChassisSerial >> 45 );
            Log( "SMBIOS: chassis serial hash -> {}", m_FieldHashes.ChassisSerial );
        }
    }

    for ( ULONG I = 0; I < m_Processor.Count; ++I )
    {
        auto& E = m_Processor.Entries[I];
        if ( !E.Valid || !E.ProcessorId )
            continue;

        m_FieldHashes.ProcessorIds[I] = HashBytes(
            reinterpret_cast< const UCHAR* >( &E.ProcessorId ),
            sizeof( E.ProcessorId ) );

        if ( m_FieldHashes.ProcessorIds[I] )
        {
            m_Hash ^= ( m_FieldHashes.ProcessorIds[I] << ( 23 + I * 3 ) ) |
                      ( m_FieldHashes.ProcessorIds[I] >> ( 41 - I * 3 ) );
            Log( "SMBIOS: processor[{}] hash -> {}", I, m_FieldHashes.ProcessorIds[I] );
        }
    }

    for ( ULONG I = 0; I < m_Memory.Count; ++I )
    {
        auto& D = m_Memory.Devices[I];
        if ( !D.Valid || D.SizeMb == 0 || D.SizeMb == 0xFFFF )
            continue;

        m_FieldHashes.MemorySerials[I] = HashString( D.SerialNumber );
        if ( m_FieldHashes.MemorySerials[I] )
        {
            m_Hash ^= ( m_FieldHashes.MemorySerials[I] << ( 29 + I * 2 ) ) |
                      ( m_FieldHashes.MemorySerials[I] >> ( 35 - I * 2 ) );
            Log( "SMBIOS: memory[{}] serial hash -> {}", I, m_FieldHashes.MemorySerials[I] );
        }
    }

    Log( "SMBIOS: Collect done, combined hash -> {}", m_Hash );
    return STATUS_SUCCESS;
}

ULONG64 Smbios::Hash( ) const
{
    return m_Hash;
}
