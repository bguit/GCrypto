#ifndef GCRYPTO_BLOCK_CIPHER_H
#define GCRYPTO_BLOCK_CIPHER_H

#include <QList>
#include "symmetric_cipher.h"

namespace GCipher {

    class BlockCipher: public SymmetricCipher {

    public:
        BlockCipher(uint32_t block_length, std::initializer_list<uint32_t> key_lengths_list):
                block_length_(block_length),
                available_key_lengths_(key_lengths_list) {};

        template <class Mode> EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const;
        template <class Mode> EncryptStatus Decrypt(const QByteArray &cipher, QByteArray &plain) const;

        uint32_t block_length() const { return block_length_; };
        virtual EncryptStatus EncryptBlock_(const byte *plain, byte *cipher) const = 0;
        virtual EncryptStatus DecryptBlock_(const byte *cipher, byte *plain) const = 0;

        // --- Work with key
        QByteArray key() const { return key_; };
        bool IsKeyLengthAvailable(uint32_t key_length) const;
        bool set_key(const SymmetricKey &key);

        private:
        QList<uint32_t> available_key_lengths_;

        SymmetricKey key_;
        uint32_t block_length_;
    };

    template <class Mode>
    EncryptStatus BlockCipher::Encrypt(const QByteArray &plain, QByteArray &cipher) const {
        Mode mode;
        mode.set_cipher(*this);

        return mode.Encrypt(plain, cipher);
    }
    template <class Mode>
    EncryptStatus BlockCipher::Decrypt(const QByteArray &cipher, QByteArray &plain) const {
        Mode mode;
        mode.set_cipher(*this);

        return mode.Decrypt(plain, cipher);
    }

}

#endif //GCRYPTO_BLOCK_CIPHER_H
