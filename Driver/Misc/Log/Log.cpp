#include <Misc/Incl.h>

namespace Log {
    namespace Detail {

        static SIZE_T WriteUDec( char* Dst, SIZE_T Cap, unsigned long long V )
        {
            char Tmp[20];
            SIZE_T Len = 0;
            do { Tmp[Len++] = '0' + ( char )( V % 10 ); V /= 10; } while ( V );
            SIZE_T Out = 0;
            while ( Len > 0 && Out < Cap - 1 ) Dst[Out++] = Tmp[--Len];
            Dst[Out] = '\0';
            return Out;
        }

        static SIZE_T WriteHex( char* Dst, SIZE_T Cap, unsigned long long V )
        {
            static const char HexChars[] = "0123456789abcdef";
            char Tmp[16];
            SIZE_T Len = 0;
            do { Tmp[Len++] = HexChars[V & 0xF]; V >>= 4; } while ( V );
            SIZE_T Out = 0;
            if ( Out < Cap - 1 ) Dst[Out++] = '0';
            if ( Out < Cap - 1 ) Dst[Out++] = 'x';
            while ( Len > 0 && Out < Cap - 1 ) Dst[Out++] = Tmp[--Len];
            Dst[Out] = '\0';
            return Out;
        }

        static SIZE_T CopyStr( char* Dst, SIZE_T Cap, const char* Src )
        {
            SIZE_T Out = 0;
            while ( Src[Out] && Out < Cap - 1 ) { Dst[Out] = Src[Out]; ++Out; }
            Dst[Out] = '\0';
            return Out;
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, int V )
        {
            if ( V < 0 ) { Dst[0] = '-'; return 1 + WriteUDec( Dst + 1, Cap - 1, ( unsigned long long )( -( V + 1 ) ) + 1 ); }
            return WriteUDec( Dst, Cap, ( unsigned long long )V );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, unsigned int V )
        {
            return WriteUDec( Dst, Cap, ( unsigned long long )V );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, long V )
        {
            if ( V < 0 ) { Dst[0] = '-'; return 1 + WriteUDec( Dst + 1, Cap - 1, ( unsigned long long )( -( V + 1 ) ) + 1 ); }
            return WriteUDec( Dst, Cap, ( unsigned long long )V );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, unsigned long V )
        {
            return WriteUDec( Dst, Cap, ( unsigned long long )V );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, long long V )
        {
            if ( V < 0 ) { Dst[0] = '-'; return 1 + WriteUDec( Dst + 1, Cap - 1, ( unsigned long long )( -( V + 1 ) ) + 1 ); }
            return WriteUDec( Dst, Cap, ( unsigned long long )V );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, unsigned long long V )
        {
            return WriteUDec( Dst, Cap, V );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, bool V )
        {
            return CopyStr( Dst, Cap, V ? "true" : "false" );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, const char* V )
        {
            return CopyStr( Dst, Cap, V ? V : "(null)" );
        }

        SIZE_T ConvertArg( char* Dst, SIZE_T Cap, void* V )
        {
            return WriteHex( Dst, Cap, ( unsigned long long )( ULONG_PTR )V );
        }

        void AppendRemainder( char* Buf, SIZE_T& Offset, SIZE_T Cap, const char* Fmt )
        {
            while ( *Fmt && Offset < Cap - 1 )
                Buf[Offset++] = *Fmt++;
        }

        void Build( char* Buf, SIZE_T Cap, const char* Fmt )
        {
            SIZE_T Offset = 0;
            AppendRemainder( Buf, Offset, Cap, Fmt );
            Buf[Offset] = '\0';
        }

    }
}
