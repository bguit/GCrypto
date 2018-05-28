#include <QtCore>

#include "GCipher/g_aes.h"
#include "GCipher/ecb_mode.h"

int main() {


    GCipher::AES g_aes;

    QByteArray key    = QByteArray("2111111111111111");
    qDebug() << g_aes.set_key(key);


    QByteArray plain  = QByteArray("1111111111111111");
    QByteArray cipher;

    g_aes.Encrypt<GCipher::ECB>(plain, cipher);

    qDebug() << cipher.toHex();
    return 0;
}