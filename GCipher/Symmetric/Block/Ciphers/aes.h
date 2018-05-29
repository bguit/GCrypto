#ifndef GCRYPTO_G_AES_H
#define GCRYPTO_G_AES_H

#include <QList>

#include "../block_cipher.h"

namespace GCipher {

    class AES: public Block {
    public:
        AES(): Block(16, {16, 24, 32}) {};

    private:
        EncryptStatus EncryptBlock_(const byte *plain, byte *cipher) const override;
        EncryptStatus DecryptBlock_(const byte *cipher, byte *plain) const override;
    };

}

#endif //GCRYPTO_G_AES_H
