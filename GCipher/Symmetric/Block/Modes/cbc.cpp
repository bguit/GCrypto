#include <Core/GError/errors.h>
#include "cbc.h"
#include "GCipher/base_cipher.h"

namespace GCipher {
    bool CBC::set_iv(const QByteArray &iv) {
        if ((block_cipher_ != nullptr) && (block_cipher_->block_length() == iv.length())) {
            iv_ = iv;
            return true;
        }
        G_FATAL("IV Length not correct!");
        return false;
    }

    EncryptStatus CBC::Encrypt(const QByteArray &plain, QByteArray &cipher) const {
        return kSuccess;
    }
}

