#include <Misc/Incl.h>
#include <Misc/Hash/Hash.h>
#include <Core/Identity/Network/Mac/Mac.h>
#include <Core/Identity/Network/Nic/Nic.h>
#include <Core/Identity/Network/Dns/Dns.h>
#include "Network.h"

ULONG64 Network::HashMac( const UCHAR* Mac, ULONG Len )
{
    if ( !Mac || Len == 0 )
        return 0;

    return Hash::Blake2b( Mac, Len );
}

NTSTATUS Network::Collect( )
{
    m_Count = 0;
    m_Hash  = 0;
    m_Dns   = {};
    RtlZeroMemory( m_Adapters, sizeof( m_Adapters ) );

    Mac::MacEntry MacEntries[Mac::MaxAdapters]{};
    Nic::NicEntry NicEntries[Nic::MaxAdapters]{};

    ULONG MacCount = Mac::Collect( MacEntries, Mac::MaxAdapters );
    ULONG NicCount = Nic::Enumerate( NicEntries, Nic::MaxAdapters );

    Dns::Collect( &m_Dns );

    ULONG Total = MacCount > NicCount ? MacCount : NicCount;
    if ( Total > MaxAdapters )
        Total = MaxAdapters;

    for ( ULONG i = 0; i < Total; ++i )
    {
        AdapterEntry& E = m_Adapters[i];

        if ( i < MacCount && MacEntries[i].Valid )
        {
            E.HashCurrentMac   = HashMac( MacEntries[i].Current,   MacEntries[i].CurrentLen );
            E.HashPermanentMac = HashMac( MacEntries[i].Permanent, MacEntries[i].PermanentLen );
            E.MacMismatch = ( E.HashCurrentMac   != 0 &&
                              E.HashPermanentMac  != 0 &&
                              E.HashCurrentMac    != E.HashPermanentMac );
        }

        if ( i < NicCount && NicEntries[i].Valid && NicEntries[i].HardwareIdLen > 0 )
        {
            E.HashHwid = Hash::Blake2b(
                reinterpret_cast< const UCHAR* >( NicEntries[i].HardwareId ),
                NicEntries[i].HardwareIdLen * sizeof( WCHAR ) );
        }

        E.Valid = E.HashCurrentMac || E.HashPermanentMac || E.HashHwid;

        if ( E.Valid )
        {
            ++m_Count;
            Log( "Network: adapter {} cur={:016X} perm={:016X} hwid={:016X} mismatch={}",
                 i, E.HashCurrentMac, E.HashPermanentMac, E.HashHwid, E.MacMismatch );
        }
    }

    // Fold all per-adapter hashes and DNS hashes into one combined hash.
    //
    ULONG64 Components[MaxAdapters * 3 + 2]{};
    ULONG   Idx = 0;

    for ( ULONG i = 0; i < MaxAdapters; ++i )
    {
        Components[Idx++] = m_Adapters[i].HashCurrentMac;
        Components[Idx++] = m_Adapters[i].HashPermanentMac;
        Components[Idx++] = m_Adapters[i].HashHwid;
    }
    Components[Idx++] = m_Dns.HashDomain;
    Components[Idx++] = m_Dns.HashHostname;

    m_Hash = Hash::Blake2b( reinterpret_cast< const UCHAR* >( Components ), Idx * sizeof( ULONG64 ) );

    Log( "Network: {} adapter(s), hash {:016X}", m_Count, m_Hash );
    return m_Count > 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

ULONG64 Network::Hash( ) const
{
    return m_Hash;
}

bool Network::IsMismatch( ) const
{
    for ( ULONG i = 0; i < MaxAdapters; ++i )
    {
        if ( m_Adapters[i].Valid && m_Adapters[i].MacMismatch )
            return true;
    }
    return false;
}

ULONG Network::Count( ) const
{
    return m_Count;
}

ULONG Network::FillAdapters( AdapterEntry* Out, ULONG Max ) const
{
    ULONG Written = 0;

    for ( ULONG i = 0; i < MaxAdapters && Written < Max; ++i )
    {
        if ( m_Adapters[i].Valid )
            Out[Written++] = m_Adapters[i];
    }
    return Written;
}
