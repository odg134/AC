#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include "ObDriver.h"

extern "C" {
    NTSYSCALLAPI NTSTATUS NTAPI ZwOpenDirectoryObject(
        PHANDLE            DirectoryHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes );

    NTSYSCALLAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
        HANDLE   DirectoryHandle,
        PVOID    Buffer,
        ULONG    Length,
        BOOLEAN  ReturnSingleEntry,
        BOOLEAN  RestartScan,
        PULONG   Context,
        PULONG   ReturnLength );
}

#define DIRECTORY_QUERY 0x0001

struct OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
};

NTSTATUS ObDriver::EnumerateDirectory( const wchar_t* Path )
{
    UNICODE_STRING Str;
    RtlInitUnicodeString( &Str, Path );
    OBJECT_ATTRIBUTES Oa;
    InitializeObjectAttributes( &Oa, &Str, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );

    HANDLE hDir;
    NTSTATUS St = ZwOpenDirectoryObject( &hDir, DIRECTORY_QUERY, &Oa );
    if ( !NT_SUCCESS( St ) )
        return St;

    constexpr ULONG BufSize = 0x2000;
    PVOID Buf = ExAllocatePoolZero( NonPagedPool, BufSize, 'DrOb' );
    if ( !Buf )
    {
        ZwClose( hDir );
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BOOLEAN Restart = TRUE;
    ULONG   Context = 0;

    for ( ;; )
    {
        ULONG RetLen = 0;
        St = ZwQueryDirectoryObject( hDir, Buf, BufSize, FALSE, Restart, &Context, &RetLen );
        Restart = FALSE;

        if ( St == STATUS_NO_MORE_ENTRIES )
            break;
        if ( !NT_SUCCESS( St ) && St != STATUS_MORE_ENTRIES )
            break;

        auto* Info = static_cast<OBJECT_DIRECTORY_INFORMATION*>( Buf );
        for ( ; Info->Name.Buffer && m_Count < MaxEntries; ++Info )
        {
            if ( !Info->Name.Length )
                break;

            m_Entries[m_Count].HashPath = 0;
            m_Entries[m_Count].HashName = Hash::Blake2b(
                reinterpret_cast<const UCHAR*>( Info->Name.Buffer ),
                Info->Name.Length );
            ++m_Count;
        }

        if ( St != STATUS_MORE_ENTRIES )
            break;
    }

    ExFreePoolWithTag( Buf, 'DrOb' );
    ZwClose( hDir );
    return STATUS_SUCCESS;
}

NTSTATUS ObDriver::Collect()
{
    m_Count = 0;
    EnumerateDirectory( L"\\Driver" );
    EnumerateDirectory( L"\\FileSystem" );
    return STATUS_SUCCESS;
}
