#ifndef GCRYPTO_CIPHER_MODE_H
#define GCRYPTO_CIPHER_MODE_H

#include <QString>
#include <QByteArray>
#include <utility>
#include "base_cipher.h"

namespace GCipher {
    class CipherMode {
        // TODO: ADD Padding!
    public:
        explicit CipherMode(QString name): name_(std::move(name)) {};

        virtual EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher,
                                      const EncryptStatus &EncryptBlock(const QByteArray&, QByteArray&)) = 0;
        virtual EncryptStatus Decrypt(const QByteArray &cipher, QByteArray &plain,
                                      const EncryptStatus &DecryptBlock(const QByteArray&, QByteArray&)) = 0;

        QString name();
    private:
        QString name_;
    };
}



#endif //GCRYPTO_CIPHER_MODE_H
