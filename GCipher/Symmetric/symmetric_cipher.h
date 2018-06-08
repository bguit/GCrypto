#ifndef GCRYPTO_GCIPHER_SYMMETRIC_H
#define GCRYPTO_GCIPHER_SYMMETRIC_H

#include "../base_cipher.h"
#include <QByteArray>

namespace GCipher {

    typedef QByteArray SymmetricKey;

    class Symmetric {

    public:
        virtual bool set_key(const SymmetricKey &key) = 0;

    private:
        SymmetricKey key_;
    };
}

#endif //GCRYPTO_GCIPHER_SYMMETRIC_H
