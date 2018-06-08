#ifndef GCRYPTO_GCIPHER_AES_H
#define GCRYPTO_GCIPHER_AES_H

#include <QList>

#include "../block_cipher.h"

namespace GCipher {

    class AES: public Block {
    public:
        AES(): Block(16, {16, 24, 32}) {};

    private:
        EncryptStatus EncryptBlock_(const byte *plain,
                                    const uint32_t* full_key, uint32_t user_key_length,
                                    byte *cipher) const override;
        EncryptStatus DecryptBlock_(const byte *cipher, const uint32_t* full_key, byte *plain) const override;

        bool KeyWrap(const QByteArray &user_key, QByteArray &full_key) const override;

    };

}

#endif //GCRYPTO_GCIPHER_AES_H
