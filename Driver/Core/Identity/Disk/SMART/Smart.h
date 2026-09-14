#pragma once
#include <ntddk.h>

namespace Smart
{
    // ATA IDENTIFY DEVICE response size in bytes.
    //
    static constexpr ULONG IdentifyBufferSize = 512;

    // Output buffer size for IOCTL_STORAGE_QUERY_PROPERTY.
    //
    static constexpr ULONG StorageDescriptorBufferSize = 1024;

    struct AtaPassThroughEx
    {
        USHORT    Length;
        USHORT    AtaFlags;
        UCHAR     PathId;
        UCHAR     TargetId;
        UCHAR     Lun;
        UCHAR     Reserved;
        ULONG     DataTransferLength;
        ULONG     TimeOutValue;
        ULONG_PTR DataBufferOffset;
        UCHAR     PreviousTaskFile[8];
        UCHAR     CurrentTaskFile[8];
    };

    struct StoragePropertyQuery
    {
        ULONG PropertyId;  // 0 = StorageDeviceProperty
        ULONG QueryType;   // 0 = PropertyStandardQuery
        UCHAR AdditionalParameters[1];
    };

    struct StorageDeviceDescriptor
    {
        ULONG   Version;
        ULONG   Size;
        UCHAR   DeviceType;
        UCHAR   DeviceTypeModifier;
        BOOLEAN RemovableMedia;
        BOOLEAN CommandQueueing;
        ULONG   VendorIdOffset;
        ULONG   ProductIdOffset;
        ULONG   ProductRevisionOffset;
        ULONG   SerialNumberOffset;
        ULONG   BusType;
        ULONG   RawPropertiesLength;
        UCHAR   RawDeviceProperties[1];
    };

    /// <summary>
    /// Sends ATA IDENTIFY DEVICE (0xEC) via IOCTL_ATA_PASS_THROUGH.
    /// On success, Buffer receives IdentifyBufferSize bytes of raw IDENTIFY data.
    /// </summary>
    /// <param name="Target"></param>
    /// <param name="Buffer"></param>
    /// <returns></returns>
    NTSTATUS SendIdentify( PDEVICE_OBJECT Target, UCHAR* Buffer );

    /// <summary>
    /// Queries StorageDeviceProperty via IOCTL_STORAGE_QUERY_PROPERTY.
    /// On success, Buffer receives a STORAGE_DEVICE_DESCRIPTOR.
    /// </summary>
    /// <param name="Target"></param>
    /// <param name="Buffer"></param>
    /// <param name="BufferSize"></param>
    /// <returns></returns>
    NTSTATUS QueryStorageDescriptor( PDEVICE_OBJECT Target, UCHAR* Buffer, ULONG BufferSize );

    /// <summary>
    /// Extracts the serial number from an IDENTIFY DEVICE response.
    /// Words 10-19 (bytes 20-39) hold the serial; each word is byte-swapped.
    /// Output is null-terminated ASCII with trailing spaces trimmed.
    /// </summary>
    /// <param name="Identify"></param>
    /// <param name="Serial"></param>
    /// <param name="SerialSize"></param>
    void ExtractIdentifySerial( const UCHAR* Identify, char* Serial, ULONG SerialSize );

    /// <summary>
    /// Returns a pointer into Buffer at the SerialNumberOffset of the
    /// STORAGE_DEVICE_DESCRIPTOR, or nullptr if the offset is invalid.
    /// </summary>
    /// <param name="Buffer"></param>
    /// <param name="BufferSize"></param>
    /// <returns></returns>
    const char* ExtractStorageSerial( const UCHAR* Buffer, ULONG BufferSize );
}
