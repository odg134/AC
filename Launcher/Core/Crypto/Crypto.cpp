#include <Misc/Incl.h>
#include "Crypto.h"

namespace Crypto
{
    // Must match Backend/src/packet/crypto.ts MODULE_KEY exactly
    //
    static const BYTE ModuleKey[32] =
    {
        0xb3, 0x7e, 0x2a, 0xc9, 0x5f, 0x01, 0xd8, 0x44,
        0xa6, 0x3c, 0x88, 0xf2, 0x17, 0xeb, 0x6d, 0x93,
        0x4a, 0xb0, 0xcc, 0x71, 0x29, 0x5e, 0x87, 0x3f,
        0xd1, 0x94, 0x62, 0xac, 0x0e, 0x57, 0xf9, 0x26,
    };

    static UINT32 RotL( UINT32 V, int N )
    {
        return ( V << N ) | ( V >> ( 32 - N ) );
    }

    static void QuarterRound( UINT32* W, int A, int B, int C, int D )
    {
        W[A] += W[B]; W[D] ^= W[A]; W[D] = RotL( W[D], 16 );
        W[C] += W[D]; W[B] ^= W[C]; W[B] = RotL( W[B], 12 );
        W[A] += W[B]; W[D] ^= W[A]; W[D] = RotL( W[D], 8 );
        W[C] += W[D]; W[B] ^= W[C]; W[B] = RotL( W[B], 7 );
    }

    static UINT32 Load32LE( const BYTE* P )
    {
        return  static_cast< UINT32 >( P[0] )
            | ( static_cast< UINT32 >( P[1] ) << 8 )
            | ( static_cast< UINT32 >( P[2] ) << 16 )
            | ( static_cast< UINT32 >( P[3] ) << 24 );
    }

    static void Block( UINT32* State, BYTE* Out )
    {
        UINT32 W[16];
        memcpy( W, State, sizeof( W ) );

        for ( int R = 0; R < 10; ++R )
        {
            QuarterRound( W, 0, 4, 8, 12 );
            QuarterRound( W, 1, 5, 9, 13 );
            QuarterRound( W, 2, 6, 10, 14 );
            QuarterRound( W, 3, 7, 11, 15 );
            QuarterRound( W, 0, 5, 10, 15 );
            QuarterRound( W, 1, 6, 11, 12 );
            QuarterRound( W, 2, 7, 8, 13 );
            QuarterRound( W, 3, 4, 9, 14 );
        }

        for ( int I = 0; I < 16; ++I )
        {
            UINT32 V = W[I] + State[I];
            Out[I * 4 + 0] = static_cast< BYTE >( V );
            Out[I * 4 + 1] = static_cast< BYTE >( V >> 8 );
            Out[I * 4 + 2] = static_cast< BYTE >( V >> 16 );
            Out[I * 4 + 3] = static_cast< BYTE >( V >> 24 );
        }
    }

    static void ChaCha20( BYTE* Data, SIZE_T Len, const BYTE* Key, const BYTE* Nonce )
    {
        UINT32 State[16];
        // ChaCha20 constant "expa nd 3 2-by te k"
        State[0] = 0x61707865u; State[1] = 0x3320646eu;
        State[2] = 0x79622d32u; State[3] = 0x6b206574u;

        for ( int I = 0; I < 8; ++I )
            State[4 + I] = Load32LE( Key + I * 4 );

        State[12] = 0;
        State[13] = Load32LE( Nonce );
        State[14] = Load32LE( Nonce + 4 );
        State[15] = Load32LE( Nonce + 8 );

        BYTE Ks[64];
        for ( SIZE_T Off = 0; Off < Len; Off += 64 )
        {
            State[12] = static_cast< UINT32 >( Off / 64 );
            Block( State, Ks );

            SIZE_T Chunk = ( std::min )( static_cast< SIZE_T >( 64 ), Len - Off );
            for ( SIZE_T I = 0; I < Chunk; ++I )
                Data[Off + I] ^= Ks[I];
        }
    }

    bool Decrypt( std::vector<BYTE>& Data )
    {
        if ( Data.size( ) <= 12 )
            return false;

        const BYTE* Nonce = Data.data( );
        BYTE* Body = Data.data( ) + 12;
        SIZE_T      Len = Data.size( ) - 12;

        ChaCha20( Body, Len, ModuleKey, Nonce );

        Data.erase( Data.begin( ), Data.begin( ) + 12 );
        return true;
    }
}
