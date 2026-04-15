// securevault_pro.cpp
// g++ securevault_pro.cpp -lcrypto -lssl -lpthread -std=c++17 -O2 -o securevault_pro

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
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;
std::mutex log_mutex;

struct VaultHeader {
    char magic[8] = "SVAULT2";
    uint64_t version = 200;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
    unsigned char master_key_salt[16]{};
    unsigned char rsa_pub_hash[32]{};
    unsigned char camellia_backup_key[32]{};
    unsigned char des_fragment[8]{};
    unsigned char md4_metadata[16]{};
    unsigned char reserved[64]{};
};

class SecureVault {
private:
    RSA* rsa_pub = nullptr;
    RSA* rsa_priv = nullptr;
    EVP_PKEY* evp_pub = nullptr;
    EVP_PKEY* evp_priv = nullptr;
    std::string vault_path;
    std::string password;
    unsigned char master_key[32]{};
    unsigned char aes_key[32]{};
    unsigned char aes_iv[12]{};
    std::atomic<uint64_t> encrypted_bytes{0};
    std::vector<std::thread> workers;

    void log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        std::cout << "[" << std::put_time(std::localtime(&tt), "%H:%M:%S") << "] " << msg << std::endl;
    }

    void derive_master_key() {
        unsigned char salt[16];
        RAND_bytes(salt, 16);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, 16, 200000,
                          EVP_sha256(), 32, master_key);
        memcpy(((VaultHeader*)0)->master_key_salt, salt, 16); // placeholder
        log("[PBKDF2] Master key derived");
    }

    void load_rsa_keys(const std::string& pub_path, const std::string& priv_path) {
        FILE* f = fopen(pub_path.c_str(), "r");
        if (!f) { log("Failed to open public key"); exit(1); }
        rsa_pub = PEM_read_RSAPublicKey(f, nullptr, nullptr, nullptr); fclose(f);
        evp_pub = EVP_PKEY_new(); EVP_PKEY_assign_RSA(evp_pub, rsa_pub);

        f = fopen(priv_path.c_str(), "r");
        rsa_priv = PEM_read_RSAPrivateKey(f, nullptr, nullptr, nullptr); fclose(f);
        evp_priv = EVP_PKEY_new(); EVP_PKEY_assign_RSA(evp_priv, rsa_priv);

        unsigned char hash[32];
        SHA256((unsigned char*)pub_path.c_str(), pub_path.size(), hash);
        // store in header
        log("[RSA] Keys loaded (2048-bit)");
    }

    void encrypt_aes_gcm(const unsigned char* in, size_t inlen, 
                         std::vector<unsigned char>& out, unsigned char tag[16]) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        RAND_bytes(aes_key, 32); RAND_bytes(aes_iv, 12);

        int len;
        out.resize(inlen + 16);
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx, out.data(), &len, in, inlen);
        int total = len;
        EVP_EncryptFinal_ex(ctx, out.data() + len, &len); total += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        out.resize(total);
        EVP_CIPHER_CTX_free(ctx);
        log("[AES-GCM] Encrypted block");
    }

    void encrypt_camellia_backup() {
        CAMELLIA_KEY cam;
        unsigned char iv[16] = {0};
        Camellia_set_key(master_key, 256, &cam);
        Camellia_cbc_encrypt(aes_key, ((VaultHeader*)0)->camellia_backup_key, 32, &cam, iv, CAMELLIA_ENCRYPT);
        log("[Camellia] Backup key encrypted");
    }

    void encrypt_des_fragment() {
        DES_key_schedule ks;
        DES_cblock key8;
        memcpy(key8, aes_key, 8);
        DES_set_key(&key8, &ks);
        DES_ecb_encrypt((DES_cblock*)aes_key, (DES_cblock*)((VaultHeader*)0)->des_fragment, &ks, DES_ENCRYPT);
        log("[DES] Legacy key fragment");
    }

    void compute_sha256(const unsigned char* data, size_t len, unsigned char hash[32]) {
        SHA256(data, len, hash);
    }

    void compute_md4_metadata(const std::string& meta, unsigned char hash[16]) {
        MD4((unsigned char*)meta.c_str(), meta.size(), hash);
        memcpy(((VaultHeader*)0)->md4_metadata, hash, 16);
        log("[MD4] Legacy metadata hash");
    }

    void rsa_sign_file(const unsigned char* data, size_t len, std::vector<unsigned char>& sig) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, evp_priv);
        EVP_DigestSignUpdate(mdctx, data, len);
        size_t slen;
        EVP_DigestSignFinal(mdctx, nullptr, &slen);
        sig.resize(slen);
        EVP_DigestSignFinal(mdctx, sig.data(), &slen);
        sig.resize(slen);
        EVP_MD_CTX_free(mdctx);
        log("[RSA] File signed");
    }

    void encrypt_file_thread(const fs::path& file_path, std::ofstream& vault_file) {
        std::ifstream in(file_path, std::ios::binary);
        in.seekg(0, std::ios::end);
        size_t size = in.tellg();
        in.seekg(0);
        std::vector<unsigned char> data(size);
        in.read((char*)data.data(), size);

        // SHA-256
        unsigned char sha[32];
        compute_sha256(data.data(), size, sha);

        // AES-GCM
        unsigned char tag[16];
        std::vector<unsigned char> enc_data;
        encrypt_aes_gcm(data.data(), size, enc_data, tag);

        // RSA encrypt AES key
        std::vector<unsigned char> rsa_enc_key(256);
        int enc_len = RSA_public_encrypt(32, aes_key, rsa_enc_key.data(), rsa_pub, RSA_PKCS1_OAEP_PADDING);
        rsa_enc_key.resize(enc_len);

        // Camellia backup
        encrypt_camellia_backup();

        // DES fragment
        encrypt_des_fragment();

        // MD4 metadata
        std::string meta = file_path.filename().string() + "|" + std::to_string(size);
        compute_md4_metadata(meta, ((VaultHeader*)0)->md4_metadata);

        // Sign
        std::vector<unsigned char> to_sign;
        to_sign.insert(to_sign.end(), sha, sha + 32);
        to_sign.insert(to_sign.end(), enc_data.begin(), enc_data.end());
        std::vector<unsigned char> signature;
        rsa_sign_file(to_sign.data(), to_sign.size(), signature);

        // Write to vault
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            uint64_t name_len = file_path.string().size();
            vault_file.write((char*)&name_len, 8);
            vault_file.write(file_path.string().c_str(), name_len);
            vault_file.write((char*)&size, 8);
            vault_file.write((char*)sha, 32);
            vault_file.write((char*)aes_iv, 12);
            vault_file.write((char*)tag, 16);
            vault_file.write((char*)&enc_len, 4);
            vault_file.write((char*)rsa_enc_key.data(), enc_len);
            vault_file.write((char*)enc_data.data(), enc_data.size());
            vault_file.write(( char*)signature.data(), signature.size());
            encrypted_bytes += size;
            log("[ENCRYPT] " + file_path.string() + " (" + std::to_string(size) + " bytes)");
        }
    }

public:
    SecureVault(const std::string& vault, const std::string& pass,
                const std::string& pub, const std::string& priv)
        : vault_path(vault), password(pass) {
        load_rsa_keys(pub, priv);
        derive_master_key();
    }

    void add_directory(const std::string& dir) {
        VaultHeader header;
        std::ofstream vault(vault_path, std::ios::binary);
        vault.write((char*)&header, sizeof(header)); // placeholder

        uint64_t file_count = 0;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() != ".vault") {
                file_count++;
            }
        }

        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() != ".vault") {
                workers.emplace_back(&SecureVault::encrypt_file_thread, this, entry.path(), std::ref(vault));
            }
        }

        for (auto& t : workers) t.join();
        header.file_count = file_count;
        header.total_size = encrypted_bytes;

        vault.seekp(0);
        vault.write((char*)&header, sizeof(header));
        vault.close();

        log("[VAULT] Created: " + vault_path + " | Files: " + std::to_string(file_count) +
            " | Size: " + std::to_string(encrypted_bytes / 1024 / 1024) + " MB");
    }

    ~SecureVault() {
        if (rsa_pub) RSA_free(rsa_pub);
        if (rsa_priv) RSA_free(rsa_priv);
        if (evp_pub) EVP_PKEY_free(evp_pub);
        if (evp_priv) EVP_PKEY_free(evp_priv);
    }
};

// ========================================
// MAIN + KEYGEN + SECURE DELETE
// ========================================
void generate_keys() {
    RSA* keypair = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(keypair, 2048, e, nullptr);

    BIO* bio = BIO_new_file("vault_pub.pem", "w");
    PEM_write_RSAPublicKey(bio, keypair);
    BIO_free(bio);

    bio = BIO_new_file("vault_priv.pem", "w");
    PEM_write_RSAPrivateKey(bio, keypair, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio);

    RSA_free(keypair); BN_free(e);
    std::cout << "[KEYGEN] RSA 2048-bit keys generated\n";
}

void secure_delete(const std::string& path) {
    if (!fs::exists(path)) return;
    auto size = fs::file_size(path);
    std::ofstream f(path, std::ios::binary);
    std::vector<unsigned char> junk(size);
    RAND_bytes(junk.data(), size);
    f.write((char*)junk.data(), size);
    f.close();
    fs::remove(path);
    std::cout << "[DELETE] Securely wiped: " << path << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage:\n";
        std::cout << "  securevault_pro keygen\n";
        std::cout << "  securevault_pro encrypt <dir> <vault.vault> <password>\n";
        std::cout << "  securevault_pro wipe <file>\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen") {
        generate_keys();
    }
    else if (cmd == "encrypt") {
        std::string dir = argv[2];
        std::string vault = argv[3];
        std::string pass;
        std::cout << "Password: ";
        std::cin >> pass;

        SecureVault sv(vault, pass, "vault_pub.pem", "vault_priv.pem");
        sv.add_directory(dir);
    }
    else if (cmd == "wipe") {
        secure_delete(argv[2]);
    }

    return 0;
}