#pragma once
#include <ntddk.h>

class Disk
{
public:
    static constexpr ULONG MaxDisks = 8;

    struct DiskSerial
    {
        ULONG64 HashAta;     // ATA IDENTIFY DEVICE (0xEC) via passthrough
        ULONG64 HashStorage; // StorageDeviceProperty path
        bool    Valid;
    };

    Disk() = default;

    /// <summary>
    /// Enumerate all physical disks and collect serials via multiple independent methods.
    /// </summary>
    /// <returns></returns>
    NTSTATUS Collect();

    /// <summary>
    /// Returns a combined hash of all collected disk serials.
    /// </summary>
    /// <returns></returns>
    ULONG64 Hash() const;

    /// <summary>
    /// Returns true if any disk reports different serials across collection methods.
    /// </summary>
    /// <returns></returns>
    bool IsMismatch() const;

    /// <summary>
    /// Number of physical disks found during Collect().
    /// </summary>
    /// <returns></returns>
    ULONG Count() const;
    ULONG FillSerials( DiskSerial* Out, ULONG Max ) const;

private:
    static ULONG64  HashSerial( const char* Serial );
    static NTSTATUS OpenDisk( ULONG Index, PFILE_OBJECT* FileObj, PDEVICE_OBJECT* DevObj );

    DiskSerial m_Serials[MaxDisks]{};
    ULONG      m_Count{};
    ULONG64    m_Hash{};
};
