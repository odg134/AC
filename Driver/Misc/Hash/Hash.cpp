#include <Misc/Incl.h>
#include <Core/Mem/Mem.h>
#include <Misc/Hash/Hash.h>

namespace Hash
{

static constexpr ULONG64 B2IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static constexpr UCHAR B2Sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

struct B2State
{
    ULONG64 h[8];
    ULONG64 t[2];
    ULONG64 f[2];
    UCHAR   buf[128];
    SIZE_T  bufLen;
    ULONG   outLen;
};

static ULONG64 Rotr64( ULONG64 x, int n ) { return ( x >> n ) | ( x << ( 64 - n ) ); }

static ULONG64 Load64( const UCHAR* p )
{
    return (ULONG64)p[0]         | ( (ULONG64)p[1] << 8  ) | ( (ULONG64)p[2] << 16 ) | ( (ULONG64)p[3] << 24 )
         | ( (ULONG64)p[4] << 32 ) | ( (ULONG64)p[5] << 40 ) | ( (ULONG64)p[6] << 48 ) | ( (ULONG64)p[7] << 56 );
}

static void Store32( UCHAR* p, ULONG v )
{
    p[0] = (UCHAR)v; p[1] = (UCHAR)( v >> 8 ); p[2] = (UCHAR)( v >> 16 ); p[3] = (UCHAR)( v >> 24 );
}

static void Store64( UCHAR* p, ULONG64 v )
{
    for ( int i = 0; i < 8; ++i, v >>= 8 ) p[i] = (UCHAR)v;
}

static void B2G( ULONG64* v, int a, int b, int c, int d, ULONG64 x, ULONG64 y )
{
    v[a] += v[b] + x;  v[d] = Rotr64( v[d] ^ v[a], 32 );
    v[c] += v[d];      v[b] = Rotr64( v[b] ^ v[c], 24 );
    v[a] += v[b] + y;  v[d] = Rotr64( v[d] ^ v[a], 16 );
    v[c] += v[d];      v[b] = Rotr64( v[b] ^ v[c], 63 );
}

static void B2Compress( B2State* S, bool Last )
{
    ULONG64 m[16], v[16];
    for ( int i = 0; i < 16; ++i ) m[i] = Load64( S->buf + i * 8 );
    for ( int i = 0; i < 8;  ++i ) v[i] = S->h[i];

    v[ 8] = B2IV[0]; v[ 9] = B2IV[1]; v[10] = B2IV[2]; v[11] = B2IV[3];
    v[12] = B2IV[4] ^ S->t[0]; v[13] = B2IV[5] ^ S->t[1];
    v[14] = Last ? ~B2IV[6] : B2IV[6];
    v[15] = B2IV[7];

    for ( int r = 0; r < 12; ++r )
    {
        B2G( v, 0, 4,  8, 12, m[B2Sigma[r][ 0]], m[B2Sigma[r][ 1]] );
        B2G( v, 1, 5,  9, 13, m[B2Sigma[r][ 2]], m[B2Sigma[r][ 3]] );
        B2G( v, 2, 6, 10, 14, m[B2Sigma[r][ 4]], m[B2Sigma[r][ 5]] );
        B2G( v, 3, 7, 11, 15, m[B2Sigma[r][ 6]], m[B2Sigma[r][ 7]] );
        B2G( v, 0, 5, 10, 15, m[B2Sigma[r][ 8]], m[B2Sigma[r][ 9]] );
        B2G( v, 1, 6, 11, 12, m[B2Sigma[r][10]], m[B2Sigma[r][11]] );
        B2G( v, 2, 7,  8, 13, m[B2Sigma[r][12]], m[B2Sigma[r][13]] );
        B2G( v, 3, 4,  9, 14, m[B2Sigma[r][14]], m[B2Sigma[r][15]] );
    }

    for ( int i = 0; i < 8; ++i ) S->h[i] ^= v[i] ^ v[i + 8];
}

static void B2Init( B2State* S, ULONG OutLen )
{
    RtlZeroMemory( S, sizeof( *S ) );
    for ( int i = 0; i < 8; ++i ) S->h[i] = B2IV[i];
    S->h[0] ^= 0x01010000ULL | (ULONG64)OutLen;
    S->outLen = OutLen;
}

static void B2Update( B2State* S, const UCHAR* Data, SIZE_T Len )
{
    while ( Len > 0 )
    {
        SIZE_T Fill = 128 - S->bufLen;
        SIZE_T Take = Len < Fill ? Len : Fill;
        RtlCopyMemory( S->buf + S->bufLen, Data, Take );
        S->bufLen += Take;
        Data      += Take;
        Len       -= Take;

        if ( S->bufLen == 128 && Len > 0 )
        {
            S->t[0] += 128;
            if ( S->t[0] < 128 ) S->t[1]++;
            B2Compress( S, false );
            S->bufLen = 0;
        }
    }
}

static void B2Final( B2State* S, UCHAR* Out )
{
    S->t[0] += (ULONG64)S->bufLen;
    if ( S->t[0] < S->bufLen ) S->t[1]++;
    RtlZeroMemory( S->buf + S->bufLen, 128 - S->bufLen );
    B2Compress( S, true );

    UCHAR Tmp[64];
    for ( int i = 0; i < 8; ++i ) Store64( Tmp + i * 8, S->h[i] );
    RtlCopyMemory( Out, Tmp, S->outLen );
}

static void B2Hash( UCHAR* Out, ULONG OutLen, const UCHAR* Data, SIZE_T DataLen )
{
    B2State S;
    B2Init( &S, OutLen );
    B2Update( &S, Data, DataLen );
    B2Final( &S, Out );
}

static void HVar( UCHAR* Out, ULONG OutLen, const UCHAR* Data, SIZE_T DataLen )
{
    UCHAR Prefix[4];
    Store32( Prefix, OutLen );

    if ( OutLen <= 64 )
    {
        B2State S;
        B2Init( &S, OutLen );
        B2Update( &S, Prefix, 4 );
        B2Update( &S, Data, DataLen );
        B2Final( &S, Out );
        return;
    }

    UCHAR A[64];
    B2State S;
    B2Init( &S, 64 );
    B2Update( &S, Prefix, 4 );
    B2Update( &S, Data, DataLen );
    B2Final( &S, A );
    RtlCopyMemory( Out, A, 32 );

    ULONG Written = 32;
    while ( OutLen - Written > 64 )
    {
        B2Hash( A, 64, A, 64 );
        RtlCopyMemory( Out + Written, A, 32 );
        Written += 32;
    }

    ULONG Remain = OutLen - Written;
    B2Hash( A, Remain, A, 64 );
    RtlCopyMemory( Out + Written, A, Remain );
}

// Argon2 G differs from Blake2b G by the extra low-32-bit multiplication.
//
static void ArgonG( ULONG64* v, int a, int b, int c, int d )
{
    v[a] += v[b] + 2ULL * (ULONG64)(ULONG)v[a] * (ULONG64)(ULONG)v[b];
    v[d]  = Rotr64( v[d] ^ v[a], 32 );
    v[c] += v[d] + 2ULL * (ULONG64)(ULONG)v[c] * (ULONG64)(ULONG)v[d];
    v[b]  = Rotr64( v[b] ^ v[c], 24 );
    v[a] += v[b] + 2ULL * (ULONG64)(ULONG)v[a] * (ULONG64)(ULONG)v[b];
    v[d]  = Rotr64( v[d] ^ v[a], 16 );
    v[c] += v[d] + 2ULL * (ULONG64)(ULONG)v[c] * (ULONG64)(ULONG)v[d];
    v[b]  = Rotr64( v[b] ^ v[c], 63 );
}

static void ArgonRound( ULONG64* v )
{
    ArgonG( v,  0,  4,  8, 12 ); ArgonG( v,  1,  5,  9, 13 );
    ArgonG( v,  2,  6, 10, 14 ); ArgonG( v,  3,  7, 11, 15 );
    ArgonG( v,  0,  5, 10, 15 ); ArgonG( v,  1,  6, 11, 12 );
    ArgonG( v,  2,  7,  8, 13 ); ArgonG( v,  3,  4,  9, 14 );
}

static void ArgonP( ULONG64* B )
{
    for ( int i = 0; i < 8; ++i ) ArgonRound( B + 16 * i );

    for ( int i = 0; i < 8; ++i )
    {
        ULONG64 v[16];
        for ( int j = 0; j < 8; ++j )
        {
            v[j * 2]     = B[2 * i + j * 16];
            v[j * 2 + 1] = B[2 * i + j * 16 + 1];
        }
        ArgonRound( v );
        for ( int j = 0; j < 8; ++j )
        {
            B[2 * i + j * 16]     = v[j * 2];
            B[2 * i + j * 16 + 1] = v[j * 2 + 1];
        }
    }
}

static void ArgonFill( ULONG64* Next, const ULONG64* Prev, const ULONG64* Ref, bool WithXor )
{
    ULONG64 R[128];
    for ( int i = 0; i < 128; ++i ) R[i] = Prev[i] ^ Ref[i];

    ULONG64 Q[128];
    RtlCopyMemory( Q, R, 1024 );
    ArgonP( Q );

    if ( WithXor )
        for ( int i = 0; i < 128; ++i ) Next[i] ^= R[i] ^ Q[i];
    else
        for ( int i = 0; i < 128; ++i ) Next[i]  = R[i] ^ Q[i];
}

static void ArgonGenIndices( ULONG64* IdxBlock, const UCHAR* H0, ULONG Pass, ULONG Lane, ULONG Slice, ULONG m, ULONG t )
{
    ULONG64 PseudoIn[128]{};
    PseudoIn[0] = (ULONG64)Pass;
    PseudoIn[1] = (ULONG64)Lane;
    PseudoIn[2] = (ULONG64)Slice;
    PseudoIn[3] = (ULONG64)m;
    PseudoIn[4] = (ULONG64)t;
    PseudoIn[5] = 1ULL; // Argon2i

    ULONG64 Zero[128]{};
    ULONG64 Tmp[128]{};
    ArgonFill( Tmp, Zero, PseudoIn, false );
    ArgonFill( IdxBlock, Zero, Tmp, false );
}

/// <summary>
/// Memory-hard hash using Argon2i.
/// </summary>
/// <param name="Data"></param>
/// <param name="DataLen"></param>
/// <param name="Salt"></param>
/// <param name="SaltLen"></param>
/// <param name="TimeCost"></param>
/// <param name="MemoryCostKB"></param>
/// <returns></returns>
ULONG64 Argon2i( const UCHAR* Data, ULONG DataLen, const UCHAR* Salt, ULONG SaltLen, ULONG TimeCost, ULONG MemoryCostKB )
{
    if ( MemoryCostKB < 8 ) MemoryCostKB = 8;

    // Must be a multiple of 4 (one segment per slice).
    //
    ULONG m = ( MemoryCostKB / 4 ) * 4;

    UCHAR H0Input[128]{};
    ULONG H0Len = 0;

    auto Push32 = [&]( ULONG v ) { Store32( H0Input + H0Len, v ); H0Len += 4; };

    Push32( 1 );        // parallelism
    Push32( 8 );        // tag length
    Push32( m );
    Push32( TimeCost );
    Push32( 0x13 );     // Argon2 version
    Push32( 1 );        // Argon2i

    Push32( DataLen );
    if ( H0Len + DataLen <= sizeof( H0Input ) )
    {
        RtlCopyMemory( H0Input + H0Len, Data, DataLen );
        H0Len += DataLen;
    }

    Push32( SaltLen );
    if ( H0Len + SaltLen <= sizeof( H0Input ) )
    {
        RtlCopyMemory( H0Input + H0Len, Salt, SaltLen );
        H0Len += SaltLen;
    }

    Push32( 0 ); // no secret
    Push32( 0 ); // no associated data

    UCHAR H0[64]{};
    B2Hash( H0, 64, H0Input, H0Len );

    // Allocate memory blocks.
    //
    SIZE_T   BlocksSize = (SIZE_T)m * 1024;
    ULONG64* Blocks     = (ULONG64*)Mem::Alloc( BlocksSize );
    if ( !Blocks )
        return 0;

    RtlZeroMemory( Blocks, BlocksSize );

    {
        UCHAR Seed[72]{};
        RtlCopyMemory( Seed, H0, 64 );
        Store32( Seed + 64, 0 );
        Store32( Seed + 68, 0 );
        HVar( (UCHAR*)( Blocks + 0 * 128 ), 1024, Seed, 72 );
    }
    {
        UCHAR Seed[72]{};
        RtlCopyMemory( Seed, H0, 64 );
        Store32( Seed + 64, 1 );
        Store32( Seed + 68, 0 );
        HVar( (UCHAR*)( Blocks + 1 * 128 ), 1024, Seed, 72 );
    }

    ULONG q = m / 4;

    for ( ULONG Pass = 0; Pass < TimeCost; ++Pass )
    {
        for ( ULONG Slice = 0; Slice < 4; ++Slice )
        {
            ULONG64 IdxBlock[128]{};
            ArgonGenIndices( IdxBlock, H0, Pass, 0, Slice, m, TimeCost );

            for ( ULONG s = 0; s < q; ++s )
            {
                ULONG Cur  = Slice * q + s;
                if ( Pass == 0 && Cur < 2 )
                    continue;

                ULONG   Prev  = ( Cur == 0 ) ? m - 1 : Cur - 1;
                ULONG64 J1    = IdxBlock[s % 128] & 0xFFFFFFFFULL;
                ULONG   RSize = ( Pass == 0 ) ? ( Slice * q + s ) : ( m - q );
                if ( RSize == 0 ) RSize = 1;
                ULONG64 z     = ( J1 * J1 ) >> 32;
                ULONG   Ref   = (ULONG)( ( RSize - 1 ) - ( ( (ULONG64)RSize * z ) >> 32 ) );
                if ( Pass > 0 || Slice > 0 )
                    Ref = Ref % m;

                ArgonFill( Blocks + Cur * 128, Blocks + Prev * 128, Blocks + Ref * 128, Pass > 0 );
            }
        }
    }

    ULONG64 Final[128]{};
    RtlCopyMemory( Final, Blocks + ( m - 1 ) * 128, 1024 );
    for ( ULONG i = 0; i < m - 1; ++i )
        for ( int j = 0; j < 128; ++j )
            Final[j] ^= Blocks[i * 128 + j];

    UCHAR Tag[8]{};
    HVar( Tag, 8, (UCHAR*)Final, 1024 );

    Mem::Free( Blocks );

    return Load64( Tag );
}

/// <summary>
/// Blake2b 64-bit hash.
/// </summary>
/// <param name="Data"></param>
/// <param name="DataLen"></param>
/// <returns></returns>
ULONG64 Blake2b( const UCHAR* Data, ULONG DataLen )
{
    UCHAR Out[8]{};
    B2Hash( Out, 8, Data, DataLen );
    return Load64( Out );
}

} // namespace Hash
