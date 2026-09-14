#pragma once
#include <ntddk.h>
#include <Core/Dispatch/Packet/Packet.h>

namespace Packet
{
    class Queue
    {
    public:
        static constexpr ULONG Capacity = 64;

        bool Enqueue( const Raw& Pkt );
        bool Dequeue( Raw* Out );
        ULONG Count( ) const;

    private:
        void EnsureInit( );

        Raw        m_Buf[Capacity]{};
        ULONG      m_Head{};
        ULONG      m_Tail{};
        ULONG      m_Count{};
        KSPIN_LOCK m_Lock{};
        bool       m_Init{};
    };

    inline Queue g_Queue;
}
