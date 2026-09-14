#pragma once
#include <ntddk.h>

namespace Dns
{
    struct DnsInfo
    {
        ULONG64 HashDomain;    // DNS domain suffix (e.g. "corp.contoso.com")
        ULONG64 HashHostname;  // machine hostname
        bool    Valid;
    };

    /// <summary>
    /// Reads DNS domain suffix and hostname from the Tcpip registry parameters.
    /// </summary>
    NTSTATUS Collect( DnsInfo* Out );
}
