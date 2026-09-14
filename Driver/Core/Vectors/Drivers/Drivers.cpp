#include <Misc/Incl.h>
#include "Drivers.h"
#include "PsModuleList/PsModuleList.h"
#include "SysQuery/SysQuery.h"
#include "ObDriver/ObDriver.h"
#include "SvcReg/SvcReg.h"
#include "UnloadedList/UnloadedList.h"
#include "PiDDB/PiDDB.h"

NTSTATUS Drivers::Collect()
{
    m_Count = 0;

    {
        PsModuleList S;
        S.Collect();
        for ( ULONG I = 0; I < S.Count(); ++I )
            TryAdd( S.Data()[I].HashPath, S.Data()[I].HashName, false );
    }
    {
        SysQuery S;
        S.Collect();
        for ( ULONG I = 0; I < S.Count(); ++I )
            TryAdd( S.Data()[I].HashPath, S.Data()[I].HashName, false );
    }
    {
        ObDriver S;
        S.Collect();
        for ( ULONG I = 0; I < S.Count(); ++I )
            TryAdd( S.Data()[I].HashPath, S.Data()[I].HashName, false );
    }
    {
        SvcReg S;
        S.Collect();
        for ( ULONG I = 0; I < S.Count(); ++I )
            TryAdd( S.Data()[I].HashPath, S.Data()[I].HashName, false );
    }
    {
        UnloadedList S;
        S.Collect();
        for ( ULONG I = 0; I < S.Count(); ++I )
            TryAdd( S.Data()[I].HashPath, S.Data()[I].HashName, true );
    }
    {
        PiDDB S;
        S.Collect();
        for ( ULONG I = 0; I < S.Count(); ++I )
            TryAdd( S.Data()[I].HashPath, S.Data()[I].HashName, false );
    }

    Log( "Drivers: collected {} unique entries", m_Count );
    return STATUS_SUCCESS;
}

ULONG Drivers::FillEntries( Entry* Out, ULONG Max ) const
{
    ULONG N = min( m_Count, Max );
    for ( ULONG I = 0; I < N; ++I )
        Out[I] = m_Entries[I];
    return N;
}

void Drivers::TryAdd( ULONG64 HashPath, ULONG64 HashName, bool IsUnloaded )
{
    if ( !HashName || m_Count >= MaxEntries )
        return;

    for ( ULONG I = 0; I < m_Count; ++I )
    {
        if ( m_Entries[I].HashName == HashName )
        {
            if ( IsUnloaded )
                m_Entries[I].IsUnloaded = true;
            return;
        }
    }

    m_Entries[m_Count++] = { HashPath, HashName, IsUnloaded };
}
