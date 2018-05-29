#include "g_aes.h"

namespace GCipher {

    EncryptStatus AES::EncryptBlock_(const byte *plain, byte *cipher) const {
        if (key().isEmpty()) {
            //qDebug() << "Key is Empty!";
            return kServiceError;
        }


        for (int i = 0; i < block_length(); i++) {
            cipher[i] = plain[i] ^ key().at(i);
        }
        return kSuccess;
    }

    EncryptStatus AES::DecryptBlock_(const byte *cipher, byte *plain) const {
        if (key().isEmpty()) {
            //qDebug() << "Key is Empty!";
            return kServiceError;
        }

        for (int i = 0; i < block_length(); i++) {
            plain[i] = cipher[i] ^ key().at(i);
        }
        return kSuccess;
    }

}
