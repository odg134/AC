#include <Misc/Incl.h>
#include <Core/Identity/Identity.h>

bool Identity::Add( ULONG64 Hash )
{
    if ( m_Count >= MaxEntries )
        return false;

    for ( ULONG i = 0; i < MaxEntries; ++i )
    {
        if ( !m_Table[i].Valid )
        {
            m_Table[i] = { Hash, true };
            ++m_Count;
            return true;
        }
    }

    return false;
}

bool Identity::Remove( ULONG64 Hash )
{
    for ( ULONG i = 0; i < MaxEntries; ++i )
    {
        if ( m_Table[i].Valid && m_Table[i].Hash == Hash )
        {
            m_Table[i] = {};
            --m_Count;
            return true;
        }
    }

    return false;
}

bool Identity::Contains( ULONG64 Hash ) const
{
    for ( ULONG i = 0; i < MaxEntries; ++i )
    {
        if ( m_Table[i].Valid && m_Table[i].Hash == Hash )
            return true;
    }

    return false;
}

void Identity::Clear( )
{
    for ( auto& Entry : m_Table )
        Entry = {};

    m_Count = 0;
}

ULONG Identity::Count( ) const
{
    return m_Count;
}
