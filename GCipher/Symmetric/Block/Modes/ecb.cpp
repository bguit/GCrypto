#include "ecb.h"

namespace GCipher {

    EncryptStatus ECB::Encrypt(const QByteArray &plain, QByteArray &cipher) const {

        if (block_cipher_ == nullptr) {
            G_FATAL("Cipher is not set");
            return kServiceError;
        }

        // --- Wrap Key ---
        if (block_cipher_->key().isEmpty()) {
            G_FATAL("Key is not set");
            return kServiceError;
        }
        QByteArray full_key;
        if (!block_cipher_->KeyWrap(block_cipher_->key(), full_key)) {
            G_FATAL("Problem with Key Wrap");
            return kServiceError;
        }
        auto user_key_length = (uint32_t)(block_cipher_->key().length() * 8);

        // TODO: Update with padding
        uint32_t block_size = block_cipher_->block_length();
        uint32_t parts = plain.length() / block_size;
        uint32_t pad_length = ((parts + 1) * block_size - plain.length()) % block_size;

        auto plain_data_ptr = (const byte*)plain.constData();
        auto cipher_data = new byte[block_size * parts];

        // --- Encrypt All Blocks except the non-full ---
        auto *full_key_ptr = (uint32_t*)full_key.constData();
        for (uint32_t block_index = 0; block_index < parts; ++block_index) {
            block_cipher_->EncryptBlock_(plain_data_ptr + block_size * block_index,
                                         full_key_ptr, user_key_length,
                                         cipher_data + block_size * block_index);
        }
        // --- Padding and Encrypt non-full block
        if(pad_length != 0) {
            auto last_plane_block = new byte[block_size];
            memcpy(last_plane_block, plain_data_ptr + block_size * parts, block_size - pad_length);
            // Padding Here
            memset(last_plane_block + block_size - pad_length, 0, pad_length);

            block_cipher_->EncryptBlock_(last_plane_block,
                                         full_key_ptr, user_key_length,
                                         cipher_data + block_size * parts);

            delete[] last_plane_block;

            cipher = QByteArray((char*)cipher_data, (parts + 1) * block_size);
        } else {
            cipher = QByteArray((char*)cipher_data, parts * block_size);
        }

        delete[] cipher_data;

        return kSuccess;
    }

}
