#pragma once
#include <ntddk.h>

namespace Crypto
{
    struct Key { UCHAR Bytes[32]; };
    struct Nonce { UCHAR Bytes[12]; };

    //TODO: fill this with server negotiated key 
    //
    extern const Key SessionKey;

    Nonce NonceFromSequence( UINT32 Seq );

    void Stream( PVOID Data, ULONG Size, const Key& K, const Nonce& N );
    inline void Encrypt( PVOID D, ULONG S, const Key& K, const Nonce& N ) { Stream( D, S, K, N ); }
    inline void Decrypt( PVOID D, ULONG S, const Key& K, const Nonce& N ) { Stream( D, S, K, N ); }
}
