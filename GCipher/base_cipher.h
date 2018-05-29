#ifndef GCRYPTO_GCIPHER_BASE_H
#define GCRYPTO_GCIPHER_BASE_H

namespace GCipher {
    typedef unsigned char byte;

    enum EncryptStatus { kSuccess, kServiceError, kMacError };
}

#endif //GCRYPTO_GCIPHER_BASE_H
