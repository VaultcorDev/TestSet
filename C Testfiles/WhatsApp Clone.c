// whatsapp_clone.c — gcc whatsapp_clone.c -lcrypto -lssl -lpthread -o whatsapp_clone
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void whatsapp_send(const char* msg, RSA* my_priv, RSA* peer_pub) {
    // 1. SHA-256 message ID
    unsigned char msg_id[32];
    SHA256((unsigned char*)msg, strlen(msg), msg_id);

    // 2. AES-256-CBC encrypt
    unsigned char aes_key[32], iv[16];
    RAND_bytes(aes_key, 32); RAND_bytes(iv, 16);
    AES_KEY enc; AES_set_encrypt_key(aes_key, 256, &enc);
    int len = ((strlen(msg) + 15)/16)*16;
    unsigned char* enc_msg = malloc(len);
    AES_cbc_encrypt((unsigned char*)msg, enc_msg, len, &enc, iv, AES_ENCRYPT);

    // 3. RSA encrypt AES key
    unsigned char rsa_key[256];
    int rsa_len = RSA_public_encrypt(32, aes_key, rsa_key, peer_pub, RSA_PKCS1_OAEP_PADDING);

    // 4. Camellia encrypt backup
    unsigned char cam_key[32];
    CAMELLIA_KEY cam; Camellia_set_key(aes_key, 256, &cam);
    Camellia_encrypt(aes_key, cam_key, &cam);

    // 5. DES encrypt first 8 bytes
    unsigned char des_key[8];
    DES_key_schedule ks; DES_cblock dkey; memcpy(dkey, aes_key, 8);
    DES_set_key(&dkey, &ks); DES_ecb_encrypt((DES_cblock*)aes_key, (DES_cblock*)des_key, &ks, DES_ENCRYPT);

    // 6. MD4 for legacy logging
    unsigned char md4[16];
    MD4((unsigned char*)msg, strlen(msg), md4);

    // 7. Sign with private key
    unsigned char sig[256]; unsigned int slen;
    RSA_sign(NID_sha256, msg_id, 32, sig, &slen, my_priv);

    // Output (simulate send)
    printf("WHATSAPP SEND:\n");
    printf("  MSG_ID: "); for(int i=0;i<32;i++) printf("%02x", msg_id[i]); printf("\n");
    printf("  AES_KEY (RSA): "); for(int i=0;i<rsa_len;i++) printf("%02x", rsa_key[i]); printf("\n");
    printf("  CAMELLIA_BACKUP: "); for(int i=0;i<32;i++) printf("%02x", cam_key[i]); printf("\n");
    printf("  DES_FRAG: "); for(int i=0;i<8;i++) printf("%02x", des_key[i]); printf("\n");
    printf("  MD4_LOG: "); for(int i=0;i<16;i++) printf("%02x", md4[i]); printf("\n");
    printf("  SIGNATURE: "); for(int i=0;i<slen;i++) printf("%02x", sig[i]); printf("\n");
    printf("  DATA: "); for(int i=0;i<len;i++) printf("%02x", enc_msg[i]); printf("\n");

    free(enc_msg);
}

int main() {
    RSA* alice_priv = PEM_read_RSAPrivateKey(fopen("alice_priv.pem", "r"), NULL, NULL, NULL);
    RSA* bob_pub = PEM_read_RSAPublicKey(fopen("bob_pub.pem", "r"), NULL, NULL, NULL);
    whatsapp_send("Hello from WhatsApp!", alice_priv, bob_pub);
    return 0;
}