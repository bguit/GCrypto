#include "block_cipher.h"

namespace GCipher {

    void BlockCipher::set_mode(const GCipher::CipherMode &mode) {
        mode_ = mode;
    }

    EncryptStatus BlockCipher::Encrypt(const QByteArray &plain, QByteArray &cipher) {
        return mode_.Encrypt(plain, cipher, (const EncryptStatus& (*)(const QByteArray&, QByteArray&))EncryptBlock);
    }
    EncryptStatus BlockCipher::Decrypt(const QByteArray &cipher, QByteArray &plain) {
        return mode_.Decrypt(cipher, plain, (const EncryptStatus& (*)(const QByteArray&, QByteArray&))DecryptBlock);
    }

}

