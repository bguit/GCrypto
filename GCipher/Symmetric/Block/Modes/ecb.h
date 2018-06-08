#ifndef GCRYPTO_GMODE_ECB_H
#define GCRYPTO_GMODE_ECB_H

#include "cipher_mode.h"

namespace GCipher {

    class ECB: public CipherMode {
    public:
        ECB() = default;

        EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher) const override;

    private:

    };
}

#endif //GCRYPTO_GMODE_ECB_H
