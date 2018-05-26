#ifndef GCRYPTO_ECB_MODE_H
#define GCRYPTO_ECB_MODE_H

#include "cipher_mode.h"

namespace GCipher {

    class ECBMode: public CipherMode {
    public:
        ECBMode(): CipherMode("ECB") {};
        EncryptStatus Encrypt(const QByteArray &plain, QByteArray &cipher,
                              const EncryptStatus& EncryptBlock(const QByteArray&, QByteArray&)) override;
        EncryptStatus Decrypt(const QByteArray &cipher, QByteArray &plain,
                              const EncryptStatus& DecryptBlock(const QByteArray&, QByteArray&)) override;
    private:

    };

    typedef ECBMode ECB;
}




#endif //GCRYPTO_ECB_MODE_H
