#include <Misc/Incl.h>
#include <Core/Identity/Disk/SMART/Smart.h>

namespace Smart
{

    static constexpr ULONG IOCTL_ATA_PASS_THROUGH = 0x0004D02Cu;
    static constexpr ULONG IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400u;

    // ATA task file indices.
    //
    static constexpr UCHAR TF_Count = 1;
    static constexpr UCHAR TF_Command = 6;

    static constexpr UCHAR CMD_IDENTIFY_DEVICE = 0xEC;

    static constexpr USHORT ATA_FLAG_DRDY_REQUIRED = 0x01;
    static constexpr USHORT ATA_FLAG_DATA_IN = 0x02;

    /// <summary>
    /// Sends a synchronous IOCTL to Target, blocking until completion.
    /// </summary>
    /// <param name="Target"></param>
    /// <param name="IoctlCode"></param>
    /// <param name="InBuf"></param>
    /// <param name="InLen"></param>
    /// <param name="OutBuf"></param>
    /// <param name="OutLen"></param>
    /// <returns></returns>
    static NTSTATUS SendIoctl(
        PDEVICE_OBJECT Target,
        ULONG IoctlCode,
        PVOID InBuf,
        ULONG InLen,
        PVOID OutBuf,
        ULONG OutLen )
    {
        KEVENT Event{};
        IO_STATUS_BLOCK Iosb{};

        KeInitializeEvent( &Event, NotificationEvent, FALSE );

        // Setup the io control request...
        //
        IRP* Irp = IoBuildDeviceIoControlRequest( IoctlCode, Target, InBuf, InLen, OutBuf, OutLen, FALSE, &Event, &Iosb );
        if ( !Irp )
            return STATUS_INSUFFICIENT_RESOURCES;

        NTSTATUS Status = IofCallDriver( Target, Irp );
        if ( Status == STATUS_PENDING )
        {
            KeWaitForSingleObject( &Event, Executive, KernelMode, FALSE, nullptr );
            Status = Iosb.Status;
        }

        return Status;
    }

    /// <summary>
    /// Sends ATA IDENTIFY DEVICE (0xEC) via IOCTL_ATA_PASS_THROUGH.
    /// On success, Buffer receives IdentifyBufferSize bytes of raw IDENTIFY data.
    /// </summary>
    /// <param name="Target"></param>
    /// <param name="Buffer"></param>
    /// <returns></returns>
    NTSTATUS SendIdentify( PDEVICE_OBJECT Target, UCHAR* Buffer )
    {
        // The request is the AtaPassThroughEx header...
        //
        static constexpr SIZE_T TotalSize = sizeof( AtaPassThroughEx ) + IdentifyBufferSize;

        UCHAR Request[TotalSize]{};
        auto* Apt = reinterpret_cast< AtaPassThroughEx* >( Request );

        Apt->Length = sizeof( AtaPassThroughEx );
        Apt->AtaFlags = ATA_FLAG_DRDY_REQUIRED | ATA_FLAG_DATA_IN;
        Apt->DataTransferLength = IdentifyBufferSize;
        Apt->TimeOutValue = 10;
        Apt->DataBufferOffset = sizeof( AtaPassThroughEx );

        Apt->CurrentTaskFile[TF_Count] = 1;
        Apt->CurrentTaskFile[TF_Command] = CMD_IDENTIFY_DEVICE;

        NTSTATUS Status = SendIoctl( Target, IOCTL_ATA_PASS_THROUGH, Request, TotalSize, Request, TotalSize );
        if ( NT_SUCCESS( Status ) )
            RtlCopyMemory( Buffer, Request + sizeof( AtaPassThroughEx ), IdentifyBufferSize );
        else
            LogWarn( "Smart: ATA identify failed: {}", Status );

        return Status;
    }

    /// <summary>
    /// Queries StorageDeviceProperty via IOCTL_STORAGE_QUERY_PROPERTY.
    /// On success, Buffer receives a STORAGE_DEVICE_DESCRIPTOR.
    /// </summary>
    /// <param name="Target"></param>
    /// <param name="Buffer"></param>
    /// <param name="BufferSize"></param>
    /// <returns></returns>
    NTSTATUS QueryStorageDescriptor( PDEVICE_OBJECT Target, UCHAR* Buffer, ULONG BufferSize )
    {
        StoragePropertyQuery Query{};
        NTSTATUS Status = SendIoctl( Target, IOCTL_STORAGE_QUERY_PROPERTY, &Query, sizeof( Query ), Buffer, BufferSize );
        if ( !NT_SUCCESS( Status ) )
            LogWarn( "Smart: storage query failed: {}", Status );
        return Status;
    }

    /// <summary>
    /// Extracts the serial number from an IDENTIFY DEVICE response.
    /// </summary>
    /// <param name="Identify"></param>
    /// <param name="Serial"></param>
    /// <param name="SerialSize"></param>
    void ExtractIdentifySerial( const UCHAR* Identify, char* Serial, ULONG SerialSize )
    {
        constexpr ULONG SerialOffset = 20;
        constexpr ULONG SerialLen = 20;

        ULONG Out = 0;
        for ( ULONG i = 0; i < SerialLen && Out + 2 <= SerialSize - 1; i += 2 )
        {
            // Each word is stored with the high byte first in the IDENTIFY buffer,
            // so we swap to get correct ASCII order.
            //
            Serial[Out++] = static_cast< char >( Identify[SerialOffset + i + 1] );
            Serial[Out++] = static_cast< char >( Identify[SerialOffset + i] );
        }

        // Trim trailing spaces.
        //
        while ( Out > 0 && Serial[Out - 1] == ' ' )
            --Out;

        Serial[Out] = '\0';
    }

    /// <summary>
    /// Returns a pointer into Buffer at the SerialNumberOffset of the
    /// STORAGE_DEVICE_DESCRIPTOR, or nullptr if the offset is invalid.
    /// </summary>
    /// <param name="Buffer"></param>
    /// <param name="BufferSize"></param>
    /// <returns></returns>
    const char* ExtractStorageSerial( const UCHAR* Buffer, ULONG BufferSize )
    {
        if ( BufferSize < sizeof( StorageDeviceDescriptor ) )
            return nullptr;

        auto* Desc = reinterpret_cast< const StorageDeviceDescriptor* >( Buffer );
        if ( Desc->SerialNumberOffset == 0 || Desc->SerialNumberOffset >= BufferSize )
            return nullptr;

        return reinterpret_cast< const char* >( Buffer + Desc->SerialNumberOffset );
    }

}
