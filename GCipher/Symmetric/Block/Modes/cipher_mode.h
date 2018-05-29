#ifndef GCRYPTO_GMODE_CIPHER_MODE_H
#define GCRYPTO_GMODE_CIPHER_MODE_H

#include <QByteArray>
#include <Core/GError/errors.h>
#include "GCipher/Symmetric/Block/block_cipher.h"

namespace GMode {

    class CipherMode {
        // TODO: ADD Padding!

    public:
        CipherMode() = default;

        virtual GCipher::EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const = 0;

        bool set_block_cipher(const GCipher::Block &block_cipher);

    protected:
        const GCipher::Block* block_cipher_{nullptr};
    };
}


#endif //GCRYPTO_GMODE_CIPHER_MODE_H
