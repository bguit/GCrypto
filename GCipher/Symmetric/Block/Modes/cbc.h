#ifndef GCRYPTO_GMODE_CBC_H
#define GCRYPTO_GMODE_CBC_H

#include "cipher_mode.h"

namespace GMode {
    class CBC: public CipherMode {
    public:
        CBC() {
            iv_ = QByteArray(block_cipher_->block_length(), '\x00');
        };
        bool set_iv(const QByteArray& iv);

        GCipher::EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const override;

    private:
        QByteArray iv_;
    };
}




#endif //GCRYPTO_GMODE_CBC_H
