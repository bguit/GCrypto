#include "aes_core.h"
#include "aes_core_local.h"
#include "Core/GError/errors.h"

namespace GCipher {

    uint32_t aes_full_key_length(uint32_t key_length) {
        uint32_t num_rounds = 10 + ((key_length - 128) >> 5);
        return (num_rounds + 1) * (key_length >> 5);
    }

    template <u32 key_length>
    bool aes_key_wrap(const byte *user_key, u32* rk) {

        rk[0] = GET_U32(user_key     );
        rk[1] = GET_U32(user_key +  4);
        rk[2] = GET_U32(user_key +  8);
        rk[3] = GET_U32(user_key + 12);

        u32 temp;
        int i = 0;
        if (key_length == 128) {
            while (1) {
                temp  = rk[3];
                rk[4] = rk[0] ^
                        (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                        (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                        (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                        (Te1[(temp >> 24)       ] & 0x000000ff) ^
                        rcon[i];
                rk[5] = rk[1] ^ rk[4];
                rk[6] = rk[2] ^ rk[5];
                rk[7] = rk[3] ^ rk[6];
                if (++i == 10) {
                    return true;
                }
                rk += 4;
            }
        }
        rk[4] = GET_U32(user_key + 16);
        rk[5] = GET_U32(user_key + 20);
        if (key_length == 192) {
            while (1) {
                temp = rk[ 5];
                rk[ 6] = rk[ 0] ^
                         (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                         (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                         (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                         (Te1[(temp >> 24)       ] & 0x000000ff) ^
                         rcon[i];
                rk[ 7] = rk[ 1] ^ rk[ 6];
                rk[ 8] = rk[ 2] ^ rk[ 7];
                rk[ 9] = rk[ 3] ^ rk[ 8];
                if (++i == 8) {
                    return true;
                }
                rk[10] = rk[ 4] ^ rk[ 9];
                rk[11] = rk[ 5] ^ rk[10];
                rk += 6;
            }
        }
        rk[6] = GET_U32(user_key + 24);
        rk[7] = GET_U32(user_key + 28);
        if (key_length == 256) {
            while (1) {
                temp = rk[ 7];
                rk[ 8] = rk[ 0] ^
                         (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                         (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                         (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                         (Te1[(temp >> 24)       ] & 0x000000ff) ^
                         rcon[i];
                rk[ 9] = rk[ 1] ^ rk[ 8];
                rk[10] = rk[ 2] ^ rk[ 9];
                rk[11] = rk[ 3] ^ rk[10];
                if (++i == 7) {
                    return true;
                }
                temp = rk[11];
                rk[12] = rk[ 4] ^
                         (Te2[(temp >> 24)       ] & 0xff000000) ^
                         (Te3[(temp >> 16) & 0xff] & 0x00ff0000) ^
                         (Te0[(temp >>  8) & 0xff] & 0x0000ff00) ^
                         (Te1[(temp      ) & 0xff] & 0x000000ff);
                rk[13] = rk[ 5] ^ rk[12];
                rk[14] = rk[ 6] ^ rk[13];
                rk[15] = rk[ 7] ^ rk[14];

                rk += 8;
            }
        }
        G_FATAL("Strange wrap!");
        return false;
    }

    template<u32 key_length>
    EncryptStatus aes_encrypt(const byte *plain, const u32 *rk, byte *cipher) {

        if (rk == nullptr) {
            G_FATAL("Key is NullPointer!");
            return kServiceError;
        }
        if (plain == nullptr) {
            G_FATAL("Plain is NullPointer!");
            return kServiceError;
        }
        if (cipher == nullptr) {
            G_FATAL("Cipher is NullPointer!");
            return kServiceError;
        }
        const auto num_rounds = 10 + ((key_length - 128) >> 5);

        u32 s0, s1, s2, s3, t0, t1, t2, t3;

        s0 = GET_U32(plain     ) ^ rk[0];
        s1 = GET_U32(plain +  4) ^ rk[1];
        s2 = GET_U32(plain +  8) ^ rk[2];
        s3 = GET_U32(plain + 12) ^ rk[3];

        /* round 1: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
        /* round 2: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
        /* round 3: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
        /* round 4: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
        /* round 5: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
        /* round 6: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
        /* round 7: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
        /* round 8: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
        /* round 9: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
        if (num_rounds > 10) {
            /* round 10: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
            /* round 11: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
            if (num_rounds > 12) {
                /* round 12: */
                s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
                s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
                s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
                s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
                /* round 13: */
                t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
                t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
                t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
                t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
            }
        }
        rk += num_rounds << 2;

        s0 =
                (Te2[(t0 >> 24)       ] & 0xff000000) ^
                (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t3      ) & 0xff] & 0x000000ff) ^
                rk[0];
        PUT_U32(cipher     , s0);
        s1 =
                (Te2[(t1 >> 24)       ] & 0xff000000) ^
                (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t0      ) & 0xff] & 0x000000ff) ^
                rk[1];
        PUT_U32(cipher +  4, s1);
        s2 =
                (Te2[(t2 >> 24)       ] & 0xff000000) ^
                (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t1      ) & 0xff] & 0x000000ff) ^
                rk[2];
        PUT_U32(cipher +  8, s2);
        s3 =
                (Te2[(t3 >> 24)       ] & 0xff000000) ^
                (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t2      ) & 0xff] & 0x000000ff) ^
                rk[3];
        PUT_U32(cipher + 12, s3);

        return kSuccess;
    }

}

namespace GCipher {
    EncryptStatus aes_encrypt_128(const byte *plain, const u32 *full_key, byte *cipher) {
        return aes_encrypt<128>(plain, full_key, cipher);
    }
    EncryptStatus aes_encrypt_192(const byte *plain, const u32 *full_key, byte *cipher) {
        return aes_encrypt<192>(plain, full_key, cipher);
    }
    EncryptStatus aes_encrypt_256(const byte *plain, const u32 *full_key, byte *cipher) {
        return aes_encrypt<256>(plain, full_key, cipher);
    }

    bool aes_key_wrap_128(const byte *user_key, uint32_t* rk){
        return aes_key_wrap<128>(user_key, rk);
    }
    bool aes_key_wrap_192(const byte *user_key, uint32_t* rk){
        return aes_key_wrap<128>(user_key, rk);
    }
    bool aes_key_wrap_256(const byte *user_key, uint32_t* rk){
        return aes_key_wrap<128>(user_key, rk);
    }
}

bool GCipher::aes_test() {
    uint8_t AES128_TEST_KEY[]   = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    uint8_t AES192_TEST_KEY[]   = { 0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
                                    0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
                                    0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
    uint8_t AES256_TEST_KEY[]   = { 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                                    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                                    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                                    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };

    uint8_t AES_TEST_PLAIN[]    = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                                    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };

    uint8_t CIPHER128_EXPECTED[]    = { 0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
                                        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97 };
    uint8_t CIPHER192_EXPECTED[]    = { 0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,
                                        0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc };
    uint8_t CIPHER256_EXPECTED[]    = { 0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
                                        0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8 };



    byte cipher[16];

    // Test 128 bit
    u32 *full_key_128 = new u32[aes_full_key_length(128)];
    aes_key_wrap<128>(AES128_TEST_KEY, full_key_128);
    aes_encrypt<128>(AES_TEST_PLAIN, full_key_128, cipher);
    bool flag_test_128 = (memcmp(CIPHER128_EXPECTED, cipher, 16) == 0);
    delete[] full_key_128;

    // Test 192 bit
    u32 *full_key_192 = new u32[aes_full_key_length(192)];
    aes_key_wrap<192>(AES192_TEST_KEY, full_key_192);
    aes_encrypt<192>(AES_TEST_PLAIN, full_key_192, cipher);
    bool flag_test_192 = (memcmp(CIPHER192_EXPECTED, cipher, 16) == 0);
    delete[] full_key_192;

    // Test 256 bit
    u32 *full_key_256 = new u32[aes_full_key_length(256)];
    aes_key_wrap<256>(AES256_TEST_KEY, full_key_256);
    aes_encrypt<256>(AES_TEST_PLAIN, full_key_256, cipher);
    bool flag_test_256 = (memcmp(CIPHER256_EXPECTED, cipher, 16) == 0);
    delete[] full_key_256;

    return flag_test_128 && flag_test_192 && flag_test_256;
}