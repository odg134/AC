#pragma once
#include <ntddk.h>
#include <Core/Identity/Network/Mac/Mac.h>
#include <Core/Identity/Network/Dns/Dns.h>

class Network
{
public:
    static constexpr ULONG MaxAdapters = Mac::MaxAdapters;

    struct AdapterEntry
    {
        ULONG64 HashCurrentMac;    // hash of the current (active) MAC
        ULONG64 HashPermanentMac;  // hash of the burned-in hardware MAC
        ULONG64 HashHwid;          // hash of the NIC hardware/vendor ID string
        bool    Valid;
        bool    MacMismatch;       // current != permanent (possible spoofing)
    };

    Network( ) = default;

    /// <summary>
    /// Collects MAC addresses via NDIS internal structures and hardware IDs
    /// via the network adapter registry class key.
    /// </summary>
    NTSTATUS Collect( );

    /// <summary>
    /// Combined hash of all collected adapter entries and DNS info.
    /// </summary>
    ULONG64 Hash( ) const;

    /// <summary>
    /// Returns true if any adapter has a current MAC that differs from its
    /// permanent MAC, indicating a possible MAC spoof.
    /// </summary>
    bool IsMismatch( ) const;

    /// <summary>
    /// Number of adapters collected during the last Collect() call.
    /// </summary>
    ULONG Count( ) const;

    ULONG FillAdapters( AdapterEntry* Out, ULONG Max ) const;

    const Dns::DnsInfo& DnsData( ) const { return m_Dns; }

private:
    static ULONG64 HashMac( const UCHAR* Mac, ULONG Len );

    AdapterEntry m_Adapters[MaxAdapters]{};
    Dns::DnsInfo m_Dns{};
    ULONG        m_Count{};
    ULONG64      m_Hash{};
};
