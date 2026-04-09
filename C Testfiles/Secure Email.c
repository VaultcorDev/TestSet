// smime_email.c — gcc smime_email.c -lcrypto -lssl -o smime_email
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <stdio.h>
#include <string.h>

void smime_sign_encrypt(const char *msg, RSA *priv, RSA *pub_recipient, FILE *out) {
    // 1. SHA-256 hash message
    unsigned char sha_hash[32];
    SHA256((unsigned char*)msg, strlen(msg), sha_hash);

    // 2. MD4 hash for legacy header
    unsigned char md4_hash[16];
    MD4((unsigned char*)msg, strlen(msg), md4_hash);

    // 3. Generate AES-256 key
    unsigned char aes_key[32], aes_iv[16];
    RAND_bytes(aes_key, 32); RAND_bytes(aes_iv, 16);

    // 4. Encrypt message with AES-256-CBC
    AES_KEY enc; AES_set_encrypt_key(aes_key, 256, &enc);
    int len = strlen(msg), outlen = ((len + 15)/16)*16;
    unsigned char *enc_msg = malloc(outlen);
    AES_cbc_encrypt((unsigned char*)msg, enc_msg, outlen, &enc, aes_iv, AES_ENCRYPT);

    // 5. Encrypt AES key with RSA (recipient)
    unsigned char rsa_enc_key[256];
    int rsa_len = RSA_public_encrypt(32, aes_key, rsa_enc_key, pub_recipient, RSA_PKCS1_OAEP_PADDING);

    // 6. Backup AES key with Camellia
    unsigned char cam_enc_key[32];
    CAMELLIA_KEY cam; Camellia_set_key(aes_key, 256, &cam);
    Camellia_encrypt(aes_key, cam_enc_key, &cam);

    // 7. Legacy DES encrypt first 8 bytes
    unsigned char des_enc[8];
    DES_key_schedule ks; DES_cblock dkey;
    memcpy(dkey, aes_key, 8);
    DES_set_key(&dkey, &ks);
    DES_ecb_encrypt((DES_cblock*)aes_key, (DES_cblock*)des_enc, &ks, DES_ENCRYPT);

    // 8. Sign hash with RSA
    unsigned char sig[256];
    unsigned int siglen;
    RSA_sign(NID_sha256, sha_hash, 32, sig, &siglen, priv);

    // Output package
    fprintf(out, "-----BEGIN SMIME-----\n");
    fprintf(out, "SHA256: "); for(int i=0;i<32;i++) fprintf(out, "%02x", sha_hash[i]); fprintf(out, "\n");
    fprintf(out, "MD4: "); for(int i=0;i<16;i++) fprintf(out, "%02x", md4_hash[i]); fprintf(out, "\n");
    fprintf(out, "AES-IV: "); for(int i=0;i<16;i++) fprintf(out, "%02x", aes_iv[i]); fprintf(out, "\n");
    fprintf(out, "RSA-KEY: "); for(int i=0;i<rsa_len;i++) fprintf(out, "%02x", rsa_enc_key[i]); fprintf(out, "\n");
    fprintf(out, "CAMELLIA-KEY: "); for(int i=0;i<32;i++) fprintf(out, "%02x", cam_enc_key[i]); fprintf(out, "\n");
    fprintf(out, "DES-KEY: "); for(int i=0;i<8;i++) fprintf(out, "%02x", des_enc[i]); fprintf(out, "\n");
    fprintf(out, "SIGNATURE: "); for(int i=0;i<siglen;i++) fprintf(out, "%02x", sig[i]); fprintf(out, "\n");
    fprintf(out, "DATA: "); for(int i=0;i<outlen;i++) fprintf(out, "%02x", enc_msg[i]); fprintf(out, "\n");
    fprintf(out, "-----END SMIME-----\n");

    free(enc_msg);
    printf("[S/MIME] Email signed & encrypted\n");
}

int main() {
    const char *msg = "Confidential: Project X launches tomorrow.";
    RSA *priv = PEM_read_RSAPrivateKey(fopen("alice_priv.pem", "r"), NULL, NULL, NULL);
    RSA *pub = PEM_read_RSAPublicKey(fopen("bob_pub.pem", "r"), NULL, NULL, NULL);
    FILE *out = fopen("email.smime", "w");
    smime_sign_encrypt(msg, priv, pub, out);
    fclose(out); RSA_free(priv); RSA_free(pub);
    return 0;
}