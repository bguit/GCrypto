#ifndef GCRYPTO_CIPHER_MODE_H
#define GCRYPTO_CIPHER_MODE_H

#include <QByteArray>
#include "block_cipher.h"
#include "symmetric_cipher.h"

namespace GCipher {

    class CipherMode {
        // TODO: ADD Padding!
    public:
        virtual EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const = 0;

        void set_cipher(const BlockCipher &block_cipher);
        const BlockCipher *block_cipher_;
    private:

    };
}



#endif //GCRYPTO_CIPHER_MODE_H
