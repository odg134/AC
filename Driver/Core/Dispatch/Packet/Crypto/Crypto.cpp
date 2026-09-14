#include <Misc/Incl.h>
#include "Crypto.h"

namespace Crypto
{
    const Key SessionKey = { {
        0x6A, 0xC3, 0xF7, 0x2B, 0x8D, 0x14, 0xE9, 0x55,
        0x3F, 0xA1, 0x72, 0xC8, 0x0B, 0xD4, 0x91, 0x6E,
        0xB2, 0x47, 0xDA, 0x83, 0x1C, 0x90, 0x5A, 0xF3,
        0xE6, 0x28, 0x74, 0xCB, 0x0F, 0x39, 0xB5, 0x7D
    } };

    static constexpr UINT32 Rotl( UINT32 V, int N )
    {
        return ( V << N ) | ( V >> ( 32 - N ) );
    }

    static void QR( UINT32& A, UINT32& B, UINT32& C, UINT32& D )
    {
        A += B; D ^= A; D = Rotl( D, 16 );
        C += D; B ^= C; B = Rotl( B, 12 );
        A += B; D ^= A; D = Rotl( D, 8 );
        C += D; B ^= C; B = Rotl( B, 7 );
    }

    static UINT32 Load32( const UCHAR* P )
    {
        return ( UINT32 )P[0]
            | ( ( UINT32 )P[1] << 8 )
            | ( ( UINT32 )P[2] << 16 )
            | ( ( UINT32 )P[3] << 24 );
    }

    static void KeystreamBlock( const UINT32* St, UCHAR* Out )
    {
        UINT32 W[16];
        RtlCopyMemory( W, St, sizeof( W ) );

        for ( int R = 0; R < 10; ++R )
        {
            QR( W[0], W[4], W[8], W[12] );
            QR( W[1], W[5], W[9], W[13] );
            QR( W[2], W[6], W[10], W[14] );
            QR( W[3], W[7], W[11], W[15] );
            QR( W[0], W[5], W[10], W[15] );
            QR( W[1], W[6], W[11], W[12] );
            QR( W[2], W[7], W[8], W[13] );
            QR( W[3], W[4], W[9], W[14] );
        }

        for ( int I = 0; I < 16; ++I )
        {
            UINT32 V = W[I] + St[I];
            Out[I * 4 + 0] = ( UCHAR )( V );
            Out[I * 4 + 1] = ( UCHAR )( V >> 8 );
            Out[I * 4 + 2] = ( UCHAR )( V >> 16 );
            Out[I * 4 + 3] = ( UCHAR )( V >> 24 );
        }
    }

    Nonce NonceFromSequence( UINT32 Seq )
    {
        static constexpr UCHAR Suffix[8] = { 0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x88 };

        Nonce N{};
        N.Bytes[0] = ( UCHAR )( Seq );
        N.Bytes[1] = ( UCHAR )( Seq >> 8 );
        N.Bytes[2] = ( UCHAR )( Seq >> 16 );
        N.Bytes[3] = ( UCHAR )( Seq >> 24 );
        RtlCopyMemory( N.Bytes + 4, Suffix, 8 );
        return N;
    }

    void Stream( PVOID Data, ULONG Size, const Key& K, const Nonce& N )
    {
        // RFC 7539 ChaCha20 initial state
        //
        UINT32 St[16];
        St[0] = 0x61707865;
        St[1] = 0x3320646e;
        St[2] = 0x79622d32;
        St[3] = 0x6b206574;
        for ( int I = 0; I < 8; ++I )
            St[4 + I] = Load32( K.Bytes + I * 4 );
        St[12] = 0;
        St[13] = Load32( N.Bytes );
        St[14] = Load32( N.Bytes + 4 );
        St[15] = Load32( N.Bytes + 8 );

        auto* Ptr = static_cast< UCHAR* >( Data );

        for ( ULONG Off = 0; Off < Size; Off += 64 )
        {
            St[12] = Off / 64;

            UCHAR Ks[64];
            KeystreamBlock( St, Ks );

            ULONG Chunk = Size - Off;
            if ( Chunk > 64 ) Chunk = 64;

            for ( ULONG I = 0; I < Chunk; ++I )
                Ptr[Off + I] ^= Ks[I];
        }
    }

}
