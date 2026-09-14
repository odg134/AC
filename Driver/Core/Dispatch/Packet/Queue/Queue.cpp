#include <Misc/Incl.h>
#include "Queue.h"

namespace Packet
{
    void Queue::EnsureInit( )
    {
        if ( !m_Init )
        {
            KeInitializeSpinLock( &m_Lock );
            m_Init = true;
        }
    }

    bool Queue::Enqueue( const Raw& Pkt )
    {
        EnsureInit( );

        KIRQL Irql;
        KeAcquireSpinLock( &m_Lock, &Irql );

        if ( m_Count >= Capacity )
        {
            KeReleaseSpinLock( &m_Lock, Irql );
            LogWarn( "Packet: queue full, dropping packet (seq {})", Pkt.Hdr.Sequence );
            return false;
        }

        m_Buf[m_Tail] = Pkt;
        m_Tail = ( m_Tail + 1 ) % Capacity;
        ++m_Count;

        KeReleaseSpinLock( &m_Lock, Irql );
        return true;
    }

    bool Queue::Dequeue( Raw* Out )
    {
        EnsureInit( );

        KIRQL Irql;
        KeAcquireSpinLock( &m_Lock, &Irql );

        if ( m_Count == 0 )
        {
            KeReleaseSpinLock( &m_Lock, Irql );
            return false;
        }

        *Out = m_Buf[m_Head];
        m_Head = ( m_Head + 1 ) % Capacity;
        --m_Count;

        KeReleaseSpinLock( &m_Lock, Irql );
        return true;
    }

    ULONG Queue::Count( ) const
    {
        return m_Count;
    }
}
