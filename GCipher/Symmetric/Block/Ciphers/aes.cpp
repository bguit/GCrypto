#include "aes.h"
#include "GCipher/Symmetric/Block/Ciphers/Core/aes_core.h"
#include "Core/GError/errors.h"

namespace GCipher {

    EncryptStatus AES::EncryptBlock_(const byte *plain,
                                     const uint32_t* full_key, uint32_t user_key_length,
                                     byte *cipher) const {

        if (key().length() == 16) {
            return aes_encrypt_128(plain, full_key, cipher);
        }
        if (key().length() == 24) {
            return aes_encrypt_192(plain, full_key, cipher);
        }
        if (key().length() == 32) {
            return aes_encrypt_256(plain, full_key, cipher);
        }

        G_FATAL("Strange Key Length!");
        return kServiceError;
    }
    EncryptStatus AES::DecryptBlock_(const byte *cipher, const uint32_t* full_key, byte *plain) const {
        if (key().isEmpty()) {
            G_FATAL("Key is Empty!");
            return kServiceError;
        }

        return kSuccess;
    }

    bool AES::KeyWrap(const QByteArray &user_key, QByteArray &full_key) const {

        if (!IsKeyLengthAvailable(user_key.length())) {
            G_FATAL("Not available key length!");
            return false;
        }

        if (key().length() == 16) {
            // Num Rounds = 10 (+1), Key Length = 4 int
            uint32_t full_key_data[44];
            bool exit_flag = aes_key_wrap_128((const byte*)user_key.constData(), full_key_data);
            if (exit_flag) {
                full_key = QByteArray((char*)full_key_data, sizeof(full_key_data));
                return true;
            }
            return false;
        }
        if (key().length() == 24) {
            // Num Rounds = 12 (+1), Key Length = 6 int
            uint32_t full_key_data[78];
            bool exit_flag = aes_key_wrap_192((const byte*)user_key.constData(), full_key_data);
            if (exit_flag) {
                full_key = QByteArray((char*)full_key_data, sizeof(full_key_data));
                return true;
            }
            return false;
        }
        if (key().length() == 32) {
            // Num Rounds = 14 (+1), Key Length = 8 int
            uint32_t full_key_data[120];
            bool exit_flag = aes_key_wrap_256((const byte*)user_key.constData(), full_key_data);
            if (exit_flag) {
                full_key = QByteArray((char*)full_key_data, sizeof(full_key_data));
                return true;
            }
            return false;
        }

        G_FATAL("Not Supported key length!");
        return false;
    }

}
