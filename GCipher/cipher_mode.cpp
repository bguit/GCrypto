#include "cipher_mode.h"

namespace GCipher {

    void CipherMode::set_cipher(const BlockCipher &block_cipher) {

        block_cipher_ = &block_cipher;
    }
}