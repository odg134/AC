#pragma once
#include <ntddk.h>

class PsModuleList
{
public:
    static constexpr ULONG MaxEntries = 256;

    struct Entry {
        ULONG64 HashPath;
        ULONG64 HashName;
    };

    NTSTATUS Collect();
    ULONG    Count() const { return m_Count; }
    const Entry* Data() const { return m_Entries; }

private:
    Entry m_Entries[MaxEntries]{};
    ULONG m_Count{};
};
