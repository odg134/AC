#pragma once
#include <ntddk.h>

namespace Integrity
{
    enum class FindingKind : UCHAR
    {
        Patch    = 1,  // in-memory .text section differs from on-disk image
        CodeCave = 2,  // executable region with no pdata RUNTIME_FUNCTION coverage
        Rwx      = 3,  // PAGE_EXECUTE_READWRITE region within a loaded module
        Unbacked = 4,  // executable MEM_PRIVATE region not backed by any module
    };

    static constexpr ULONG MaxFindings = 8;

#pragma pack(push, 1)
    struct Finding
    {
        ULONG64 ModuleBase;     // runtime load address (0 for unbacked/standalone)
        ULONG   Offset;         // RVA within module (0 for standalone regions)
        ULONG   Length;         // size in bytes
        UCHAR   Kind;           // FindingKind
        CHAR    ModuleName[31]; // null-terminated base name, 0-padded
    };  // 48 bytes
#pragma pack(pop)

    struct FindingList
    {
        Finding Entries[MaxFindings];
        ULONG   Count{};

        bool Add( FindingKind Kind, PVOID Base, ULONG Offset, ULONG Length, const CHAR* Name )
        {
            if ( Count >= MaxFindings )
                return false;

            auto& F = Entries[Count++];
            F.ModuleBase = reinterpret_cast< ULONG64 >( Base );
            F.Offset     = Offset;
            F.Length     = Length;
            F.Kind       = static_cast< UCHAR >( Kind );
            RtlZeroMemory( F.ModuleName, sizeof( F.ModuleName ) );

            if ( Name )
            {
                ULONG N = 0;
                while ( Name[N] && N < sizeof( F.ModuleName ) - 1 )
                {
                    F.ModuleName[N] = Name[N];
                    ++N;
                }
            }

            return true;
        }
    };

    NTSTATUS Scan( FindingList* Out );
}
