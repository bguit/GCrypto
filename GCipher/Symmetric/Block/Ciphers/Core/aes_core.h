#ifndef GCRYPTO_GCIPHER_CORE_AES_H
#define GCRYPTO_GCIPHER_CORE_AES_H

#include <cstdint>
#include "GCipher/base_cipher.h"

namespace GCipher {
    EncryptStatus aes_encrypt_128(const byte *plain, const uint32_t *full_key, byte *cipher);
    EncryptStatus aes_encrypt_192(const byte *plain, const uint32_t *full_key, byte *cipher);
    EncryptStatus aes_encrypt_256(const byte *plain, const uint32_t *full_key, byte *cipher);

    bool aes_key_wrap_128(const byte *user_key, uint32_t* rk);
    bool aes_key_wrap_192(const byte *user_key, uint32_t* rk);
    bool aes_key_wrap_256(const byte *user_key, uint32_t* rk);

    bool aes_test();
}

#endif //GCRYPTO_GCIPHER_CORE_AES_H
