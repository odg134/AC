#pragma once
#include <ntddk.h>

class ObDriver
{
public:
    static constexpr ULONG MaxEntries = 256;

    struct Entry {
        ULONG64 HashName;
        ULONG   TimeDateStamp;
    };

    NTSTATUS Collect();
    ULONG    Count() const { return m_Count; }
    const Entry* Data() const { return m_Entries; }

private:
    NTSTATUS EnumerateDirectory(const wchar_t* Path);

    Entry m_Entries[MaxEntries]{};
    ULONG m_Count{};
};
