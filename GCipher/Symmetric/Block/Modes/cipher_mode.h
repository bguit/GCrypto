#ifndef GCRYPTO_GMODE_CIPHER_MODE_H
#define GCRYPTO_GMODE_CIPHER_MODE_H

#include <QByteArray>
#include "../block_cipher.h"
#include "../../symmetric_cipher.h"

namespace GMode {

    class CipherMode {
        // TODO: ADD Padding!

    public:
        CipherMode() = default;

        virtual GCipher::EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const = 0;

        bool set_block_cipher(const GCipher::Block &block_cipher) {
            if (block_cipher.key().isEmpty()) {
                // qDebug() << "key is empty";
                return false;
            }
            block_cipher_ = &block_cipher;
            return true;
        }

    protected:
        const GCipher::Block* block_cipher_{nullptr};
    };
}


#endif //GCRYPTO_GMODE_CIPHER_MODE_H
