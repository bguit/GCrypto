#include "block_cipher.h"
#include "Core/GError/errors.h"

namespace GCipher {

    bool Block::set_key(const SymmetricKey &key) {
        if (IsKeyLengthAvailable((uint32_t)key.length())) {
            key_ = key;
            return true;
        }
        G_FATAL("This key length is not available for this Cipher!");
        return false;
    }

    bool Block::IsKeyLengthAvailable(uint32_t key_length) const {
        return available_key_lengths_.contains(key_length);
    }

}

