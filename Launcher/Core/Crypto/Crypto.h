#pragma once
#include <windows.h>
#include <vector>

namespace Crypto
{
    /// <summary>
    /// Decrypts a module payload in-place.
    /// Wire format: [12-byte nonce][ChaCha20 ciphertext], keyed with MODULE_KEY.
    /// After the call Data holds the raw plaintext DLL with the nonce prefix stripped.
    /// </summary>
    bool Decrypt( std::vector<BYTE>& Data );
}
