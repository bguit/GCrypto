#ifndef GCRYPTO_SYMMETRIC_CIPHER_H
#define GCRYPTO_SYMMETRIC_CIPHER_H

#include "base_cipher.h"
#include <QByteArray>

namespace GCipher {

    typedef QByteArray SymmetricKey;

    class SymmetricCipher {
    public:
        //virtual EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const = 0;
        //virtual EncryptStatus Decrypt(const QByteArray &plain, QByteArray &cipher) const = 0;

        virtual void set_key(SymmetricKey key);

    private:
        SymmetricKey key_;
    };
}

#endif //GCRYPTO_SYMMETRIC_CIPHER_H
