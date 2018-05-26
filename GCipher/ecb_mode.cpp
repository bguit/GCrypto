#include "ecb_mode.h"

namespace GCipher {

    EncryptStatus ECBMode::Encrypt(const QByteArray &plain, QByteArray &cipher,
                                                     const EncryptStatus &(*EncryptBlock)(const QByteArray &,
                                                                                          QByteArray &)) {
        return kSuccess;
    }

    EncryptStatus ECBMode::Decrypt(const QByteArray &cipher, QByteArray &plain,
                                                     const EncryptStatus &(*DecryptBlock)(const QByteArray &,
                                                                                          QByteArray &)) {
        return kSuccess;
    }

}
