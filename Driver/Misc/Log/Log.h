#pragma once
#include <ntddk.h>

namespace Log {

    namespace Detail {

        static constexpr SIZE_T BufferCapacity = 512;
        static constexpr SIZE_T ArgCapacity = 64;

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, int V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, unsigned int V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, long V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, unsigned long V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, long long V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, unsigned long long V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, bool V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, const char* V );
        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, void* V );

        template<typename T>
        void AppendNextArg( char* Buf, SIZE_T& Offset, SIZE_T Cap, const char*& Fmt, T&& Val )
        {
            while ( *Fmt )
            {
                if ( Fmt[0] == '{' && Fmt[1] == '}' )
                {
                    char ArgBuf[ArgCapacity] = {};
                    SIZE_T Len = ConvertArg( ArgBuf, ArgCapacity, static_cast< T >( Val ) );
                    SIZE_T ToCopy = Len < ( Cap - Offset - 1 ) ? Len : ( Cap - Offset - 1 );
                    RtlCopyMemory( Buf + Offset, ArgBuf, ToCopy );
                    Offset += ToCopy;
                    Fmt += 2;
                    return;
                }
                if ( Offset < Cap - 1 )
                    Buf[Offset++] = *Fmt;
                ++Fmt;
            }
        }

        void AppendRemainder( char* Buf, SIZE_T& Offset, SIZE_T Cap, const char* Fmt );

        template<typename... Args>
        void Build( char* Buf, SIZE_T Cap, const char* Fmt, Args&&... ArgPack )
        {
            SIZE_T Offset = 0;
            ( AppendNextArg( Buf, Offset, Cap, Fmt, static_cast< Args&& >( ArgPack ) ), ... );
            AppendRemainder( Buf, Offset, Cap, Fmt );
            Buf[Offset] = '\0';
        }

        void Build( char* Buf, SIZE_T Cap, const char* Fmt );

    }

    enum class Level : ULONG
    {
        Trace = DPFLTR_TRACE_LEVEL,
        Info = DPFLTR_INFO_LEVEL,
        Warning = DPFLTR_WARNING_LEVEL,
        Error = DPFLTR_ERROR_LEVEL,
    };

    template<typename... Args>
    void Write( Level Lvl, const char* Fmt, Args&&... ArgPack )
    {
        char Buf[Detail::BufferCapacity] = {};
        Detail::Build( Buf, Detail::BufferCapacity, Fmt, static_cast< Args&& >( ArgPack )... );
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, static_cast< ULONG >( Lvl ), "[AC] %s\n", Buf );
    }

    template<typename... Args>
    void Trace( const char* Fmt, Args&&... ArgPack )
    {
        Write( Level::Trace, Fmt, static_cast< Args&& >( ArgPack )... );
    }

    template<typename... Args>
    void Info( const char* Fmt, Args&&... ArgPack )
    {
        Write( Level::Info, Fmt, static_cast< Args&& >( ArgPack )... );
    }

    template<typename... Args>
    void Warn( const char* Fmt, Args&&... ArgPack )
    {
        Write( Level::Warning, Fmt, static_cast< Args&& >( ArgPack )... );
    }

    template<typename... Args>
    void Error( const char* Fmt, Args&&... ArgPack )
    {
        Write( Level::Error, Fmt, static_cast< Args&& >( ArgPack )... );
    }

}

#define Log(Fmt, ...)      Log::Info(Fmt, ##__VA_ARGS__)
#define LogWarn(Fmt, ...)  Log::Warn(Fmt, ##__VA_ARGS__)
#define LogError(Fmt, ...) Log::Error(Fmt, ##__VA_ARGS__)
#define LogTrace(Fmt, ...) Log::Trace(Fmt, ##__VA_ARGS__)
