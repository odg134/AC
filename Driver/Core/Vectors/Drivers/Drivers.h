#pragma once
#include <ntddk.h>

class Drivers
{
public:
    static constexpr ULONG MaxEntries = 512;

    struct Entry {
        ULONG64 HashPath;
        ULONG64 HashName;
        bool    IsUnloaded;
    };

    NTSTATUS Collect();
    ULONG    Count() const { return m_Count; }
    ULONG    FillEntries(Entry* Out, ULONG Max) const;

private:
    void TryAdd(ULONG64 HashPath, ULONG64 HashName, bool IsUnloaded);

    Entry m_Entries[MaxEntries]{};
    ULONG m_Count{};
};
