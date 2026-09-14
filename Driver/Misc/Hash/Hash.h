#pragma once
#include <ntddk.h>

namespace Hash
{
    /// <summary>
    /// Hashes Data with Argon2i (Blake2b-based, memory-hard).
    /// MemoryCostKB must be >= 8. Returns a 64-bit digest.
    /// </summary>
    /// <param name="Data"></param>
    /// <param name="DataLen"></param>
    /// <param name="Salt"></param>
    /// <param name="SaltLen"></param>
    /// <param name="TimeCost"></param>
    /// <param name="MemoryCostKB"></param>
    /// <returns></returns>
    ULONG64 Argon2i( const UCHAR* Data, ULONG DataLen, const UCHAR* Salt, ULONG SaltLen, ULONG TimeCost, ULONG MemoryCostKB );

    /// <summary>
    /// Blake2b-based 64-bit hash, no memory hardness.
    /// </summary>
    /// <param name="Data"></param>
    /// <param name="DataLen"></param>
    /// <returns></returns>
    ULONG64 Blake2b( const UCHAR* Data, ULONG DataLen );
}
