#include "cipher_mode.h"

namespace GMode {

    bool CipherMode::set_block_cipher(const GCipher::Block &block_cipher) {
        if (block_cipher.key().isEmpty()) {
            G_FATAL("Key is Empty!");
            return false;
        }
        block_cipher_ = &block_cipher;
        return true;
    }
}