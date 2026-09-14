#pragma once
#include <ntddk.h>
#include <Core/Identity/SMBIOS/Tables/Bios/Bios.h>
#include <Core/Identity/SMBIOS/Tables/System/System.h>
#include <Core/Identity/SMBIOS/Tables/Baseboard/Baseboard.h>
#include <Core/Identity/SMBIOS/Tables/Chassis/Chassis.h>
#include <Core/Identity/SMBIOS/Tables/Processor/Processor.h>
#include <Core/Identity/SMBIOS/Tables/Memory/Memory.h>

class Smbios
{
public:
    // Per-field hashes pre-computed by Collect(); 0 for absent or junk fields.
    //
    struct FieldHashes
    {
        ULONG64 SystemSerial;
        ULONG64 BaseboardSerial;
        ULONG64 ChassisSerial;
        ULONG64 ProcessorIds[Processor::MaxProcessors];
        ULONG64 MemorySerials[Memory::MaxDevices];
    };

    Smbios( ) = default;

    /// <summary>
    /// Maps the SMBIOS table from physical memory, parses all supported
    /// structure types, and computes per-field and combined hashes.
    /// Must be called after Offsets::Init().
    /// </summary>
    NTSTATUS Collect( );

    /// <summary>
    /// Combined hash of all non-junk SMBIOS identity fields.
    /// Zero until Collect() succeeds.
    /// </summary>
    ULONG64 Hash( ) const;

    // Per-section accessors used by Telemetry::Build().
    //
    const Bios::BiosInfo&           BiosData( )      const { return m_Bios; }
    const System::SystemInfo&       SystemData( )    const { return m_System; }
    const Baseboard::BaseboardInfo& BaseboardData( ) const { return m_Baseboard; }
    const Chassis::ChassisInfo&     ChassisData( )   const { return m_Chassis; }
    const Processor::ProcessorInfo& ProcessorData( ) const { return m_Processor; }
    const Memory::MemoryInfo&       MemoryData( )    const { return m_Memory; }
    const FieldHashes&              Hashes( )        const { return m_FieldHashes; }

private:
    static ULONG64 HashString( const char* Str );
    static ULONG64 HashBytes(  const UCHAR* Bytes, ULONG Len );

    Bios::BiosInfo           m_Bios{};
    System::SystemInfo       m_System{};
    Baseboard::BaseboardInfo m_Baseboard{};
    Chassis::ChassisInfo     m_Chassis{};
    Processor::ProcessorInfo m_Processor{};
    Memory::MemoryInfo       m_Memory{};
    FieldHashes              m_FieldHashes{};
    ULONG64                  m_Hash{};
};
