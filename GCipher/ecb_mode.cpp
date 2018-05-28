#include "ecb_mode.h"

namespace GCipher {

    EncryptStatus ECB::Encrypt(const QByteArray &plain, QByteArray &cipher) const {
        if (plain.length() % 16 != 0) return kServiceError;

        auto plain_data_ptr = (const byte*)plain.constData();
        auto block_size = block_cipher_->block_length();
        auto parts = plain.length() / block_size;

        auto *cipher_data_ptr = new byte[plain.length()];

        for (uint32_t part_index = 0; part_index < parts; ++part_index) {
            block_cipher_->EncryptBlock_(plain_data_ptr + block_size * part_index, cipher_data_ptr + block_size * part_index);
        }

        cipher = QByteArray((char*)cipher_data_ptr, block_size);
        delete[] cipher_data_ptr;

        return kSuccess;
    }

}
