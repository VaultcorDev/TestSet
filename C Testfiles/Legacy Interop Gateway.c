// gateway.c — gcc gateway.c -lcrypto -lssl -o gateway
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/md4.h>

void bridge_modern_to_legacy(const unsigned char *data, int len, FILE *out) {
    // 1. SHA-256 → modern hash
    unsigned char sha[32]; SHA256(data, len, sha);

    // 2. MD4 → legacy hash
    unsigned char md4[16]; MD4(data, len, md4);

    // 3. AES-256 encrypt
    unsigned char aes_key[32]; RAND_bytes(aes_key, 32);
    unsigned char iv[16]; RAND_bytes(iv, 16);
    AES_KEY k; AES_set_encrypt_key(aes_key, 256, &k);
    int outlen = ((len + 15)/16)*16;
    unsigned char *enc = malloc(outlen);
    AES_cbc_encrypt(data, enc, outlen, &k, iv, AES_ENCRYPT);

    // 4. DES encrypt AES key (legacy)
    unsigned char des_key[8];
    DES_key_schedule ks; DES_cblock dkey;
    memcpy(dkey, aes_key, 8);
    DES_set_key(&dkey, &ks);
    DES_ecb_encrypt((DES_cblock*)aes_key, (DES_cblock*)des_key, &ks, DES_ENCRYPT);

    // 5. Camellia encrypt full key
    unsigned char cam_key[32];
    CAMELLIA_KEY ck; Camellia_set_key(aes_key, 256, &ck);
    Camellia_encrypt(aes_key, cam_key, &ck);

    // 6. RSA sign
    RSA *priv = PEM_read_RSAPrivateKey(fopen("gateway_priv.pem", "r"), NULL, NULL, NULL);
    unsigned char sig[256]; unsigned int slen;
    RSA_sign(NID_sha256, sha, 32, sig, &slen, priv);

    // Output
    fwrite(sha, 1, 32, out);
    fwrite(md4, 1, 16, out);
    fwrite(iv, 1, 16, out);
    fwrite(des_key, 1, 8, out);
    fwrite(cam_key, 1, 32, out);
    fwrite(sig, 1, slen, out);
    fwrite(enc, 1, outlen, out);

    free(enc); RSA_free(priv);
    printf("[GATEWAY] Bridged to legacy\n");
}