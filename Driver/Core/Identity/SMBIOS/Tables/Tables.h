#pragma once
#include <ntddk.h>

// Raw SMBIOS structure layouts matching the SMBIOS 3.x specification.
// All fields are packed; string offsets are 1-based indices into the
// string section that follows each structure's formatted area.

namespace Tables
{
    static constexpr UCHAR TypeBios      = 0;
    static constexpr UCHAR TypeSystem    = 1;
    static constexpr UCHAR TypeBaseboard = 2;
    static constexpr UCHAR TypeChassis   = 3;
    static constexpr UCHAR TypeProcessor = 4;
    static constexpr UCHAR TypeMemory    = 17;
    static constexpr UCHAR TypeEnd       = 127;

#pragma pack(push, 1)
    struct Header
    {
        UCHAR  Type;
        UCHAR  Length;   // size of formatted area including this header
        USHORT Handle;
    };

    struct BiosRaw
    {
        Header    Hdr;
        UCHAR     Vendor;
        UCHAR     BiosVersion;
        USHORT    BiosStartAddr;
        UCHAR     BiosReleaseDate;
        UCHAR     BiosRomSize;
        ULONGLONG Characteristics;
        UCHAR     CharExt[2];
        UCHAR     MajorRelease;
        UCHAR     MinorRelease;
        UCHAR     EmbFwMajor;
        UCHAR     EmbFwMinor;
    };

    struct SystemRaw
    {
        Header Hdr;
        UCHAR  Manufacturer;
        UCHAR  ProductName;
        UCHAR  Version;
        UCHAR  SerialNumber;
        UCHAR  UUID[16];    // raw bytes; first 4/2/2 words are LE, last 8 are BE per spec
        UCHAR  WakeUpType;
        UCHAR  SKUNumber;
        UCHAR  Family;
    };

    struct BaseboardRaw
    {
        Header Hdr;
        UCHAR  Manufacturer;
        UCHAR  Product;
        UCHAR  Version;
        UCHAR  SerialNumber;
        UCHAR  AssetTag;
        UCHAR  FeatureFlags;
        UCHAR  LocationInChassis;
        USHORT ChassisHandle;
        UCHAR  BoardType;
        UCHAR  NumContainedHandles;
    };

    struct ChassisRaw
    {
        Header Hdr;
        UCHAR  Manufacturer;
        UCHAR  Type;
        UCHAR  Version;
        UCHAR  SerialNumber;
        UCHAR  AssetTag;
    };

    struct ProcessorRaw
    {
        Header    Hdr;
        UCHAR     SocketDesignation;
        UCHAR     ProcessorType;
        UCHAR     ProcessorFamily;
        UCHAR     Manufacturer;
        ULONGLONG ProcessorId;
        UCHAR     Version;
        UCHAR     Voltage;
        USHORT    ExternalClock;
        USHORT    MaxSpeed;
        USHORT    CurrentSpeed;
        UCHAR     Status;
        UCHAR     Upgrade;
    };

    struct MemoryDeviceRaw
    {
        Header Hdr;
        USHORT PhysArrayHandle;
        USHORT MemErrHandle;
        USHORT TotalWidth;
        USHORT DataWidth;
        USHORT Size;
        UCHAR  FormFactor;
        UCHAR  DeviceSet;
        UCHAR  DeviceLocator;
        UCHAR  BankLocator;
        UCHAR  MemType;
        USHORT TypeDetail;
        USHORT Speed;
        UCHAR  Manufacturer;
        UCHAR  SerialNumber;
        UCHAR  AssetTag;
        UCHAR  PartNumber;
        UCHAR  Attributes;
        ULONG  ExtendedSize;
        USHORT ConfiguredSpeed;
    };
#pragma pack(pop)

    /// <summary>
    /// Returns the null-terminated string at the 1-based Index in the string
    /// section that follows Struct's formatted area.
    /// Returns nullptr if Index is 0, out of range, or points past TableEnd.
    /// </summary>
    const char* GetString( const UCHAR* Struct, UCHAR Index, const UCHAR* TableEnd );

    /// <summary>
    /// Advances past the current structure's formatted area and string section.
    /// Returns a pointer to the next structure, or nullptr at the table end.
    /// </summary>
    const UCHAR* NextStruct( const UCHAR* Struct, const UCHAR* TableEnd );

    /// <summary>
    /// Returns true when Str is a well-known OEM placeholder that carries no
    /// real hardware identity (e.g. "To Be Filled By O.E.M.", "Default string").
    /// </summary>
    bool IsJunk( const char* Str );
}
