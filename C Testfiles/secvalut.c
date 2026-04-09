// securevault_pro.c
// gcc securevault_pro.c -lcrypto -lssl -lpthread -std=c11 -O2 -o securevault_pro

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define VAULT_MAGIC "SVAULT2"
#define VAULT_VERSION 200
#define HEADER_SIZE 256
#define MAX_PATH 4096
#define WORKERS 8

typedef struct {
    char magic[8];
    uint16_t version;
    uint64_t file_count;
    uint64_t total_size;
    uint8_t master_salt[16];
    uint8_t rsa_pub_hash[32];
    uint8_t camellia_backup[32];
    uint8_t des_fragment[8];
    uint8_t md4_metadata[16];
    uint8_t reserved[64];
} VaultHeader;

typedef struct {
    char path[MAX_PATH];
    uint64_t size;
    uint8_t sha256[32];
    uint8_t nonce[12];
    uint8_t ciphertext[];
} __attribute__((packed)) FileEntry;

typedef struct {
    const char* input_dir;
    const char* vault_path;
    const char* password;
    const char* pub_key_path;
    const char* priv_key_path;
    VaultHeader* header;
    FILE* vault_file;
    pthread_mutex_t lock;
    uint64_t encrypted_bytes;
    int file_count;
} VaultContext;

pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void log_msg(const char* fmt, ...) {
    pthread_mutex_lock(&log_lock);
    time_t now = time(NULL);
    char timestr[20];
    strftime(timestr, sizeof(timestr), "%H:%M:%S", localtime(&now));
    printf("[%s] ", timestr);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    pthread_mutex_unlock(&log_lock);
}

void die(const char* msg) {
    log_msg("ERROR: %s", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void* xmalloc(size_t size) {
    void* p = malloc(size);
    if (!p) die("Out of memory");
    return p;
}

void derive_master_key(const char* password, uint8_t* salt, uint8_t* key) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 200000,
                           EVP_sha256(), 32, key)) {
        die("PBKDF2 failed");
    }
    log_msg("PBKDF2 Master key derived");
}

RSA* load_rsa_public(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) die("Public key not found");
    RSA* rsa = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!rsa) die("Failed to load public key");
    log_msg("RSA Public key loaded");
    return rsa;
}

RSA* load_rsa_private(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    RSA* rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (rsa) log_msg("RSA Private key loaded");
    return rsa;
}

void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash) {
    SHA256(data, len, hash);
}

void md4_hash(const uint8_t* data, size_t len, uint8_t* hash) {
    MD4(data, len, hash);
}

void aes_gcm_encrypt(const uint8_t* plaintext, size_t len,
                     uint8_t* key, uint8_t* nonce, uint8_t* ciphertext, uint8_t* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("EVP context");

    RAND_bytes(key, 32);
    RAND_bytes(nonce, 12);

    int outlen;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        die("AES init");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
        die("IV len");
    if (1 != EVP_EncryptInit_ex(ctx, NULL, key, nonce))
        die("AES key");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len))
        die("AES encrypt");
    int total = outlen;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen))
        die("AES final");
    total += outlen;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        die("AES tag");

    EVP_CIPHER_CTX_free(ctx);
    log_msg("AES-256-GCM Encrypted block");
}

void camellia_encrypt_backup(const uint8_t* aes_key, uint8_t* master_key, uint8_t* backup) {
    CAMELLIA_KEY cam;
    uint8_t iv[16] = {0};
    Camellia_set_key(master_key, 256, &cam);
    Camellia_cbc_encrypt(aes_key, backup, 32, &cam, iv, CAMELLIA_ENCRYPT);
    log_msg("Camellia Backup key encrypted");
}

void des_encrypt_fragment(const uint8_t* aes_key, uint8_t* fragment) {
    DES_key_schedule ks;
    DES_cblock key8;
    memcpy(key8, aes_key, 8);
    DES_set_key(&key8, &ks);
    DES_ecb_encrypt((DES_cblock*)aes_key, (DES_cblock*)fragment, &ks, DES_ENCRYPT);
    log_msg("DES Legacy fragment");
}

int rsa_encrypt_key(RSA* rsa, const uint8_t* aes_key, uint8_t* enc_key) {
    int len = RSA_public_encrypt(32, aes_key, enc_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) die("RSA encrypt");
    return len;
}

int rsa_sign(RSA* rsa, const uint8_t* data, size_t len, uint8_t* sig) {
    unsigned int siglen;
    if (!RSA_sign(NID_sha256, data, len, sig, &siglen, rsa))
        die("RSA sign");
    return siglen;
}

void secure_delete(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    FILE* f = fopen(path, "r+b");
    if (!f) return;
    uint8_t* junk = xmalloc(st.st_size);
    RAND_bytes(junk, st.st_size);
    fwrite(junk, 1, st.st_size, f);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    free(junk);
    remove(path);
    log_msg("DELETE Securely wiped: %s", path);
}

void* encrypt_file_worker(void* arg) {
    VaultContext* ctx = (VaultContext*)arg;
    char fullpath[MAX_PATH];
    struct dirent* entry;
    DIR* dir = opendir(ctx->input_dir);
    if (!dir) return NULL;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        snprintf(fullpath, sizeof(fullpath), "%s/%s", ctx->input_dir, entry->d_name);

        FILE* in = fopen(fullpath, "rb");
        if (!in) continue;
        fseek(in, 0, SEEK_END);
        long size = ftell(in);
        fseek(in, 0, SEEK_SET);
        uint8_t* data = xmalloc(size);
        fread(data, 1, size, in);
        fclose(in);

        // 1. SHA-256
        uint8_t sha[32];
        sha256_hash(data, size, sha);

        // 2. AES-GCM
        uint8_t aes_key[32], nonce[12], tag[16];
        uint8_t* ciphertext = xmalloc(size + 16);
        aes_gcm_encrypt(data, size, aes_key, nonce, ciphertext, tag);

        // 3. RSA encrypt key
        uint8_t rsa_enc[256];
        int rsa_len = rsa_encrypt_key(load_rsa_public(ctx->pub_key_path), aes_key, rsa_enc);

        // 4. Camellia backup
        uint8_t cam_backup[32];
        camellia_encrypt_backup(aes_key, ctx->header->master_key_salt, cam_backup);

        // 5. DES fragment
        uint8_t des_frag[8];
        des_encrypt_fragment(aes_key, des_frag);

        // 6. MD4 metadata
        char meta[512];
        snprintf(meta, sizeof(meta), "%s|%ld", entry->d_name, size);
        uint8_t md4[16];
        md4_hash((uint8_t*)meta, strlen(meta), md4);

        // 7. Sign
        uint8_t to_sign[32 + size + 16];
        memcpy(to_sign, sha, 32);
        memcpy(to_sign + 32, ciphertext, size + 16);
        uint8_t sig[256];
        int siglen = 0;
        RSA* priv = load_rsa_private(ctx->priv_key_path);
        if (priv) siglen = rsa_sign(priv, to_sign, 32 + size + 16, sig);
        if (priv) RSA_free(priv);

        // Write to vault
        pthread_mutex_lock(&ctx->lock);
        uint16_t path_len = strlen(fullpath) + 1;
        fwrite(&path_len, 1, 2, ctx->vault_file);
        fwrite(fullpath, 1, path_len, ctx->vault_file);
        fwrite(&size, 1, 8, ctx->vault_file);
        fwrite(sha, 1, 32, ctx->vault_file);
        fwrite(nonce, 1, 12, ctx->vault_file);
        fwrite(tag, 1, 16, ctx->vault_file);
        fwrite(&rsa_len, 1, 4, ctx->vault_file);
        fwrite(rsa_enc, 1, rsa_len, ctx->vault_file);
        fwrite(cam_backup, 1, 32, ctx->vault_file);
        fwrite(des_frag, 1, 8, ctx->vault_file);
        fwrite(md4, 1, 16, ctx->vault_file);
        uint16_t sig_len16 = siglen;
        fwrite(&sig_len16, 1, 2, ctx->vault_file);
        if (siglen) fwrite(sig, 1, siglen, ctx->vault_file);
        fwrite(ciphertext, 1, size + 16, ctx->vault_file);

        ctx->encrypted_bytes += size;
        ctx->file_count++;
        log_msg("ENCRYPT %s (%ld bytes)", entry->d_name, size);
        pthread_mutex_unlock(&ctx->lock);

        free(data);
        free(ciphertext);
    }
    closedir(dir);
    return NULL;
}

void create_vault(VaultContext* ctx) {
    ctx->vault_file = fopen(ctx->vault_path, "wb");
    if (!ctx->vault_file) die("Cannot create vault");

    // Placeholder header
    fseek(ctx->vault_file, HEADER_SIZE, SEEK_SET);

    // Start workers
    pthread_t threads[WORKERS];
    for (int i = 0; i < WORKERS; i++) {
        pthread_create(&threads[i], NULL, encrypt_file_worker, ctx);
    }
    for (int i = 0; i < WORKERS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Update header
    memcpy(ctx->header->magic, VAULT_MAGIC, 7);
    ctx->header->version = VAULT_VERSION;
    ctx->header->file_count = ctx->file_count;
    ctx->header->total_size = ctx->encrypted_bytes;
    RAND_bytes(ctx->header->master_salt, 16);

    fseek(ctx->vault_file, 0, SEEK_SET);
    fwrite(ctx->header, 1, sizeof(VaultHeader), ctx->vault_file);
    fclose(ctx->vault_file);

    log_msg("VAULT Created: %s | Files: %d | Size: %lu MB",
            ctx->vault_path, ctx->file_count, ctx->encrypted_bytes / 1024 / 1024);
}

void generate_keys() {
    RSA* keypair = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    if (!RSA_generate_key_ex(keypair, 2048, e, NULL)) die("Keygen failed");

    FILE* f = fopen("vault_pub.pem", "w");
    PEM_write_RSAPublicKey(f, keypair);
    fclose(f);

    f = fopen("vault_priv.pem", "w");
    PEM_write_RSAPrivateKey(f, keypair, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    RSA_free(keypair);
    BN_free(e);
    log_msg("KEYGEN RSA 2048-bit keys generated");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  securevault_pro keygen\n");
        printf("  securevault_pro encrypt <dir> <vault.vault> <password> [priv_key]\n");
        printf("  securevault_pro wipe <file>\n");
        return 1;
    }

    const char* cmd = argv[1];

    if (!strcmp(cmd, "keygen")) {
        generate_keys();
    }
    else if (!strcmp(cmd, "encrypt")) {
        if (argc < 5) die("Missing args");
        VaultContext ctx = {0};
        ctx.input_dir = argv[2];
        ctx.vault_path = argv[3];
        ctx.password = argv[4];
        ctx.pub_key_path = "vault_pub.pem";
        ctx.priv_key_path = (argc > 5) ? argv[5] : NULL;
        ctx.header = xmalloc(sizeof(VaultHeader));
        pthread_mutex_init(&ctx.lock, NULL);

        derive_master_key(ctx.password, ctx.header->master_salt, ctx.header->master_key_salt);
        create_vault(&ctx);

        pthread_mutex_destroy(&ctx.lock);
        free(ctx.header);
    }
    else if (!strcmp(cmd, "wipe")) {
        if (argc < 3) die("Missing file");
        secure_delete(argv[2]);
    }
    else {
        die("Unknown command");
    }

    return 0;
}