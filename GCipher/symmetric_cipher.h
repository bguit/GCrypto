#ifndef GCRYPTO_SYMMETRIC_CIPHER_H
#define GCRYPTO_SYMMETRIC_CIPHER_H

#include "base_cipher.h"
#include <QByteArray>

namespace GCipher {

    class SymmetricKey {
    public:
        void set_key(const QByteArray &key);

    private:
        QByteArray key_;
    };

    class SymmetricCipher {
    public:
        virtual EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const = 0;
        virtual EncryptStatus Decrypt(const QByteArray &plain, QByteArray &cipher) const = 0;

        virtual void set_key(SymmetricKey) = 0;

    private:
        SymmetricKey key_;
    };
}

#endif //GCRYPTO_SYMMETRIC_CIPHER_H
