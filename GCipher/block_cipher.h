#ifndef GCRYPTO_BLOCK_CIPHER_H
#define GCRYPTO_BLOCK_CIPHER_H

#include "symmetric_cipher.h"
#include "cipher_mode.h"

namespace GCipher {

    class BlockCipher: public SymmetricCipher {

    public:
        EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher);
        EncryptStatus Decrypt(const QByteArray &cipher, QByteArray &plain);

        void set_mode(const CipherMode &mode);

    private:
        virtual EncryptStatus EncryptBlock(const QByteArray &plain, QByteArray &cipher) = 0;
        virtual EncryptStatus DecryptBlock(const QByteArray &cipher, QByteArray &plain) = 0;

        CipherMode mode_;
    };
}

#endif //GCRYPTO_BLOCK_CIPHER_H
