#pragma once
#include <ntddk.h>

class Disk
{
public:
    Disk() = default;

    NTSTATUS Collect();
    ULONG64 Hash() const;

private:
    ULONG64 m_Hash{};
};
