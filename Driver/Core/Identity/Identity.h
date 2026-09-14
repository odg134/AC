#pragma once
#include <ntddk.h>

class Identity
{
public:
    static constexpr ULONG MaxEntries = 8;

    struct Entry
    {
        ULONG64 Hash;
        bool    Valid;
    };

    Identity( ) = default;

    bool  Add( ULONG64 Hash );
    bool  Remove( ULONG64 Hash );
    bool  Contains( ULONG64 Hash ) const;
    void  Clear( );
    ULONG Count( ) const;
    ULONG Fill( ULONG64* OutHashes, ULONG Max ) const;
private:

    // This represents the HWID table.
    Entry m_Table[MaxEntries]{};
    ULONG m_Count{};
};
