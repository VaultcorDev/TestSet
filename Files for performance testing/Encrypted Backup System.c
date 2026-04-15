// backup.c — gcc backup.c -lcrypto -lssl -o backup
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/pem.h>
#include <dirent.h>
#include <sys/stat.h>

void backup_file(const char *path, RSA *pub, FILE *archive) {
    FILE *f = fopen(path, "rb"); fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *data = malloc(sz); fread(data, 1, sz, f); fclose(f);

    // 1. SHA-256
    unsigned char sha[32]; SHA256(data, sz, sha);

    // 2. MD4 (legacy index)
    unsigned char md4[16]; MD4(data, sz, md4);

    // 3. AES-256
    unsigned char aes_key[32], iv[16]; RAND_bytes(aes_key, 32); RAND_bytes(iv, 16);
    AES_KEY k; AES_set_encrypt_key(aes_key, 256, &k);
    int outlen = ((sz + 15)/16)*16;
    unsigned char *enc = malloc(outlen);
    AES_cbc_encrypt(data, enc, outlen, &k, iv, AES_ENCRYPT);

    // 4. RSA encrypt key
    unsigned char rsa_key[256];
    int rsa_len = RSA_public_encrypt(32, aes_key, rsa_key, pub, RSA_PKCS1_OAEP_PADDING);

    // 5. Camellia backup
    unsigned char cam_key[32];
    CAMELLIA_KEY ck; Camellia_set_key(aes_key, 256, &ck);
    Camellia_encrypt(aes_key, cam_key, &ck);

    // 6. DES legacy
    unsigned char des_key[8];
    DES_key_schedule ks; DES_cblock dkey; memcpy(dkey, aes_key, 8);
    DES_set_key(&dkey, &ks);
    DES_ecb_encrypt((DES_cblock*)aes_key, (DES_cblock*)des_key, &ks, DES_ENCRYPT);

    // Write to archive
    fwrite(path, 1, strlen(path)+1, archive);
    fwrite(&sz, 1, sizeof(sz), archive);
    fwrite(sha, 1, 32, archive);
    fwrite(md4, 1, 16, archive);
    fwrite(iv, 1, 16, archive);
    fwrite(&rsa_len, 1, sizeof(int), archive);
    fwrite(rsa_key, 1, rsa_len, archive);
    fwrite(cam_key, 1, 32, archive);
    fwrite(des_key, 1, 8, archive);
    fwrite(enc, 1, outlen, archive);

    free(data); free(enc);
    printf("[BACKUP] %s\n", path);
}

int main() {
    RSA *pub = PEM_read_RSAPublicKey(fopen("backup_pub.pem", "r"), NULL, NULL, NULL);
    FILE *archive = fopen("backup.enc", "wb");
    DIR *d = opendir("."); struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG && strstr(dir->d_name, ".txt"))
            backup_file(dir->d_name, pub, archive);
    }
    fclose(archive); closedir(d); RSA_free(pub);
    return 0;
}