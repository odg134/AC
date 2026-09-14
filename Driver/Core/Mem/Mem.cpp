#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include <Core/Mem/Pool/Pool.h>

namespace Mem
{
    static Pool g_Pool;

    /// <summary>
    /// Sets up the global memory pool. Call once from DriverEntry.
    /// </summary>
    /// <param name="PoolSize"></param>
    /// <returns></returns>
    NTSTATUS Initialize( SIZE_T PoolSize )
    {
        return g_Pool.Initialize( PoolSize );
    }

    /// <summary>
    /// Tears down the pool, freeing all outstanding allocations.
    /// </summary>
    void Shutdown( )
    {
        g_Pool.Shutdown( );
    }

    /// <summary>
    /// </summary>
    /// <param name="Size"></param>
    /// <returns></returns>
    PVOID Alloc( SIZE_T Size )
    {
        return g_Pool.Allocate( Size );
    }

    /// <summary>
    /// </summary>
    /// <param name="Ptr"></param>
    void Free( PVOID Ptr )
    {
        g_Pool.Release( Ptr );
    }

} // namespace Mem
