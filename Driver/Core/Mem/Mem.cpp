#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include <Core/Mem/Pool/Pool.h>

namespace Mem
{

static Pool g_Pool;

/// <summary>
/// Sets up the global memory pool.
/// </summary>
/// <param name="PoolSize"></param>
/// <returns></returns>
NTSTATUS Initialize( SIZE_T PoolSize )
{
    NTSTATUS Status = g_Pool.Initialize( PoolSize );
    if ( NT_SUCCESS( Status ) )
        Log( "Mem: pool initialized ({} bytes)", PoolSize );
    else
        LogError( "Mem: pool initialization failed: {}", Status );
    return Status;
}

/// <summary>
/// Tears down the pool.
/// </summary>
void Shutdown( )
{
    g_Pool.Shutdown( );
    Log( "Mem: pool shutdown" );
}

/// <summary>
/// </summary>
/// <param name="Size"></param>
/// <returns></returns>
PVOID Alloc( SIZE_T Size )
{
    PVOID Ptr = g_Pool.Allocate( Size );
    if ( !Ptr )
        LogError( "Mem: allocation failed ({} bytes)", Size );
    return Ptr;
}

/// <summary>
/// </summary>
/// <param name="Ptr"></param>
void Free( PVOID Ptr )
{
    g_Pool.Release( Ptr );
}

}
