#ifndef GCRYPTO_GCIPHER_BLOCK_H
#define GCRYPTO_GCIPHER_BLOCK_H

#include <QList>
#include "../symmetric_cipher.h"

namespace GCipher {

    class Block: public Symmetric {

    public:
        Block(): block_length_(0), available_key_lengths_({0}) {};
        Block(uint32_t block_length, std::initializer_list<uint32_t> key_lengths_list):
                block_length_(block_length),
                available_key_lengths_(key_lengths_list) {};

        uint32_t block_length() const { return block_length_; };
        virtual EncryptStatus EncryptBlock_(const byte *plain, byte *cipher) const = 0;
        virtual EncryptStatus DecryptBlock_(const byte *cipher, byte *plain) const = 0;

        // --- Work with key
        QByteArray key() const { return key_; };
        bool IsKeyLengthAvailable(uint32_t key_length) const;
        bool set_key(const SymmetricKey &key) override;

        private:
        QList<uint32_t> available_key_lengths_;

        SymmetricKey key_;
        uint32_t block_length_;
    };

}

#endif //GCRYPTO_GCIPHER_BLOCK_H
