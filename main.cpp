#include <QtCore>
#include "Core/GError/errors.h"
#include "GCipher/Symmetric/Block/Ciphers/aes.h"
#include "GCipher/Symmetric/Block/Modes/ecb.h"

int main() {


    GCipher::AES g_aes;

    QByteArray key    = QByteArray("21111111111111");
    g_aes.set_key(key);

    QByteArray plain  = QByteArray("1111111111111111");
    QByteArray cipher;

    GMode::ECB g_ecb;
    g_ecb.set_block_cipher(g_aes);
    g_ecb.Encrypt(plain, cipher);
    if (!cipher.isEmpty()) {
        qDebug() << "Cipher Text:" << cipher.toHex();
    } else {
        G_WARNING("Encrypting Fail");
    }

    QTextStream error_stream(stderr);
    GErrorList::Print(error_stream);


    return 0;
}