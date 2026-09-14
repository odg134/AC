#pragma once
#include <ntddk.h>

// Placement new/delete for Mem::New<T>.
//
inline void* operator new( SIZE_T, void* Ptr ) noexcept { return Ptr; }
inline void  operator delete( void*, void* )   noexcept {}

namespace Mem
{
    /// <summary>
    /// Sets up the global memory pool. Call once from DriverEntry.
    /// </summary>
    /// <param name="PoolSize"></param>
    /// <returns></returns>
    NTSTATUS Initialize( SIZE_T PoolSize );

    /// <summary>
    /// Tears down the pool, freeing all outstanding allocations.
    /// </summary>
    void Shutdown();

    PVOID Alloc( SIZE_T Size );
    void  Free( PVOID Ptr );

    template<typename T, typename... Args>
    T* New( Args&&... ArgPack )
    {
        PVOID Ptr = Alloc( sizeof( T ) );
        if ( !Ptr ) return nullptr;
        return ::new( Ptr ) T( static_cast<Args&&>( ArgPack )... );
    }

    template<typename T>
    void Delete( T* Ptr )
    {
        if ( !Ptr ) return;
        Ptr->~T();
        Free( Ptr );
    }

    template<typename T>
    struct UniquePtr
    {
        UniquePtr() = default;
        explicit UniquePtr( T* Ptr ) : m_Ptr( Ptr ) {}
        ~UniquePtr() { if ( m_Ptr ) { Delete( m_Ptr ); m_Ptr = nullptr; } }

        UniquePtr( const UniquePtr& ) = delete;
        UniquePtr& operator=( const UniquePtr& ) = delete;

        UniquePtr( UniquePtr&& Other ) noexcept : m_Ptr( Other.m_Ptr ) { Other.m_Ptr = nullptr; }

        T*   operator->() const { return m_Ptr; }
        T&   operator*()  const { return *m_Ptr; }
        T*   Get()        const { return m_Ptr; }
        explicit operator bool() const { return m_Ptr != nullptr; }

    private:
        T* m_Ptr{};
    };

    struct RawPtr
    {
        RawPtr() = default;
        explicit RawPtr( SIZE_T Size ) : m_Ptr( Alloc( Size ) ) {}
        ~RawPtr() { if ( m_Ptr ) { Free( m_Ptr ); m_Ptr = nullptr; } }

        RawPtr( const RawPtr& ) = delete;
        RawPtr& operator=( const RawPtr& ) = delete;

        template<typename T> T* As() const { return static_cast<T*>( m_Ptr ); }
        explicit operator bool() const { return m_Ptr != nullptr; }

    private:
        PVOID m_Ptr{};
    };
}
