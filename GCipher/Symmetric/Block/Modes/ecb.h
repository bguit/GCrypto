#ifndef GCRYPTO_GMODE_ECB_H
#define GCRYPTO_GMODE_ECB_H

#include "cipher_mode.h"

namespace GMode {

    class ECB: public CipherMode {
    public:
        ECB() = default;

        GCipher::EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const override;

    private:

    };
}

#endif //GCRYPTO_GMODE_ECB_H
