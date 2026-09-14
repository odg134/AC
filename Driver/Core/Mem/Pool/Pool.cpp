#include <Misc/Incl.h>
#include <Core/Mem/Pool/Pool.h>

namespace Mem
{
    static constexpr ULONG PoolTag = 'pMCA';

    /// <summary>
    /// Allocates the backing slab and sets up the free list.
    /// </summary>
    /// <param name="Size"></param>
    /// <returns></returns>
    NTSTATUS Pool::Initialize( SIZE_T Size )
    {
        m_Base = ( UCHAR* )ExAllocatePool2( POOL_FLAG_NON_PAGED, Size, PoolTag );
        if ( !m_Base )
            return STATUS_INSUFFICIENT_RESOURCES;

        m_Capacity = Size;
        KeInitializeSpinLock( &m_Lock );

        m_Head = ( Block* )m_Base;
        m_Head->Size = Size - sizeof( Block );
        m_Head->Free = true;
        m_Head->Next = nullptr;

        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Frees the backing slab, cleaning up any outstanding allocations.
    /// </summary>
    void Pool::Shutdown( )
    {
        if ( m_Base )
        {
            ExFreePoolWithTag( m_Base, PoolTag );
            m_Base = nullptr;
            m_Head = nullptr;
        }
    }

    /// <summary>
    /// </summary>
    /// <param name="Size"></param>
    /// <returns></returns>
    PVOID Pool::Allocate( SIZE_T Size )
    {
        // Align to pointer width.
        //
        Size = ( Size + sizeof( PVOID ) - 1 ) & ~( sizeof( PVOID ) - 1 );

        KIRQL Irql;
        KeAcquireSpinLock( &m_Lock, &Irql );

        for ( Block* Cur = m_Head; Cur; Cur = Cur->Next )
        {
            if ( !Cur->Free || Cur->Size < Size )
                continue;

            // Split if there's room for a new block header and at least one word of payload.
            //
            if ( Cur->Size >= Size + sizeof( Block ) + sizeof( PVOID ) )
            {
                Block* Split = ( Block* )( ( UCHAR* )( Cur + 1 ) + Size );
                Split->Size = Cur->Size - Size - sizeof( Block );
                Split->Free = true;
                Split->Next = Cur->Next;
                Cur->Size = Size;
                Cur->Next = Split;
            }

            Cur->Free = false;
            KeReleaseSpinLock( &m_Lock, Irql );
            return ( PVOID )( Cur + 1 );
        }

        KeReleaseSpinLock( &m_Lock, Irql );
        return nullptr;
    }

    /// <summary>
    /// </summary>
    /// <param name="Ptr"></param>
    void Pool::Release( PVOID Ptr )
    {
        if ( !Ptr )
            return;

        Block* Blk = ( Block* )Ptr - 1;

        KIRQL Irql;
        KeAcquireSpinLock( &m_Lock, &Irql );

        Blk->Free = true;

        // Coalesce adjacent free blocks forward.
        //
        for ( Block* Cur = m_Head; Cur; )
        {
            if ( Cur->Free && Cur->Next && Cur->Next->Free )
            {
                Cur->Size += sizeof( Block ) + Cur->Next->Size;
                Cur->Next = Cur->Next->Next;
            }
            else
            {
                Cur = Cur->Next;
            }
        }

        KeReleaseSpinLock( &m_Lock, Irql );
    }

} // namespace Mem
