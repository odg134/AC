#pragma once
#include <ntddk.h>

namespace Mem
{
    class Pool
    {
    public:
        Pool() = default;

        /// <summary>
        /// Allocates the backing slab and sets up the free list.
        /// </summary>
        /// <param name="Size"></param>
        /// <returns></returns>
        NTSTATUS Initialize( SIZE_T Size );

        /// <summary>
        /// Frees the backing slab, cleaning up any outstanding allocations.
        /// </summary>
        void Shutdown();

        PVOID Allocate( SIZE_T Size );
        void  Release( PVOID Ptr );

    private:
        struct Block
        {
            SIZE_T Size;
            bool   Free;
            Block* Next;
        };

        UCHAR*     m_Base{};
        Block*     m_Head{};
        SIZE_T     m_Capacity{};
        KSPIN_LOCK m_Lock{};
    };
}
