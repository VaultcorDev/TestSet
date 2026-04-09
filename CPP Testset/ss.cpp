// messaging.cpp — g++ messaging.cpp -lcrypto -lssl -o messaging_cpp
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/pem.h>

void send_message(const std::string& msg, RSA* priv, RSA* pub) {
    static unsigned char chain_key[32] = "initial12345678901234567890123456";
    unsigned char msg_key[32]; SHA256(chain_key, 32, msg_key);

    unsigned char iv[16]; RAND_bytes(iv, 16);
    AES_KEY k; AES_set_encrypt_key(msg_key, 256, &k);
    int len = ((msg.size() + 15)/16)*16; std::vector<unsigned char> enc(len);
    AES_cbc_encrypt((unsigned char*)msg.c_str(), enc.data(), len, &k, iv, AES_ENCRYPT);

    unsigned char sig[256]; unsigned int slen; RSA_sign(NID_sha256, (unsigned char*)msg.c_str(), msg.size(), sig, &slen, priv);

    unsigned char cam[32]; CAMELLIA_KEY camk; Camellia_set_key(msg_key, 256, &camk); Camellia_encrypt(msg_key, cam, &camk);
    unsigned char des[8]; DES_key_schedule ks; DES_cblock dkey; memcpy(dkey, msg_key, 8);
    DES_set_key(&dkey, &ks); DES_ecb_encrypt((DES_cblock*)iv, (DES_cblock*)des, &ks, DES_ENCRYPT);

    unsigned char md4[16]; MD4((unsigned char*)msg.c_str(), msg.size(), md4);

    std::ofstream f("msg_cpp.enc", std::ios::binary);
    f.write((char*)iv, 16); f.write((char*)enc.data(), len); f.write((char*)sig, slen);
    f.write((char*)cam, 32); f.write((char*)des, 8); f.write((char*)md4, 16);
}