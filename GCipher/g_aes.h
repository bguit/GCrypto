#ifndef GCRYPTO_G_AES_H
#define GCRYPTO_G_AES_H

#include "block_cipher.h"

namespace GCipher {

    class AES: public BlockCipher {
    public:
        EncryptStatus EncryptBlock(const QByteArray &plain, QByteArray &cipher) override;
        EncryptStatus DecryptBlock(const QByteArray &cipher, QByteArray &plain) override;
    private:
        SymmetricKey key_;
    };


}

#endif //GCRYPTO_G_AES_H
