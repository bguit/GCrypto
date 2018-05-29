#include <QtCore>

#include "GCipher/Symmetric/Block/Ciphers/g_aes.h"
#include "GCipher/Symmetric/Block/Modes/ecb.h"

int main() {


    GCipher::AES g_aes;

    QByteArray key    = QByteArray("2111111111111111");
    g_aes.set_key(key);

    QByteArray plain  = QByteArray("1111111111111111");
    QByteArray cipher;

    GMode::ECB g_ecb;
    g_ecb.set_block_cipher(g_aes);
    g_ecb.Encrypt(plain, cipher);

    qDebug() << cipher.toHex();
    return 0;
}