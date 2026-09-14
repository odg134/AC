#pragma once
#include <ntddk.h>

struct KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY     InLoadOrderLinks;
    UCHAR          _pad10[0x20];
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    ULONG          _pad44;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    UCHAR          _pad6E[0x92];
    LIST_ENTRY     HashLinks;
};
