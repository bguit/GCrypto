#include "block_cipher.h"

namespace GCipher {

    bool BlockCipher::set_key(const SymmetricKey &key) {
        if (IsKeyLengthAvailable((uint32_t)key.length())) {
            key_ = key;
            return true;
        }

        return false;
    }

    bool BlockCipher::IsKeyLengthAvailable(uint32_t key_length) const {
        return available_key_lengths_.contains(key_length);
    }

}

