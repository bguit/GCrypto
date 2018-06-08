#ifndef GCRYPTO_GMODE_CIPHER_MODE_H
#define GCRYPTO_GMODE_CIPHER_MODE_H

#include <QByteArray>
#include <Core/GError/errors.h>
#include "GCipher/Symmetric/Block/block_cipher.h"

namespace GCipher {

    class CipherMode {
        // TODO: ADD Padding!

    public:
        CipherMode() = default;

        virtual EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const = 0;

        bool set_block_cipher(const Block &block_cipher);

    protected:
        const Block* block_cipher_{nullptr};
    };
}


#endif //GCRYPTO_GMODE_CIPHER_MODE_H
