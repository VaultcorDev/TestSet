// g++ encrypt.cpp -lcrypto -o encrypt
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <iostream>

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::string& password) {
    unsigned char salt[16], key[32], iv[12];
    RAND_bytes(salt, sizeof(salt));
    RAND_bytes(iv, sizeof(iv));

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "PBKDF2", nullptr);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_derive(kctx, key, 32, 
        EVP_KDF_password(kctx, (const unsigned char*)password.c_str(), password.size()),
        EVP_KDF_salt(kctx, salt, 16),
        EVP_KDF_iter(kctx, 100000),
        EVP_KDF_digest(kctx, "SHA256"));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, key, iv);

    std::vector<uint8_t> out(data.size() + 16);
    int len;
    EVP_EncryptUpdate(ctx, out.data(), &len, data.data(), data.size());
    int total = len;
    EVP_EncryptFinal_ex(ctx, out.data() + len, &len); total += len;

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    // Format: salt || iv || ciphertext || tag
    std::vector<uint8_t> result;
    result.insert(result.end(), salt, salt + 16);
    result.insert(result.end(), iv, iv + 12);
    result.insert(result.end(), out.begin(), out.begin() + total);
    result.insert(result.end(), tag, tag + 16);

    EVP_KDF_CTX_free(kctx); EVP_KDF_free(kdf); EVP_CIPHER_CTX_free(ctx);
    return result;
}

int main() {
    std::string msg = "Top secret data";
    auto enc = encrypt({msg.begin(), msg.end()}, "my-password");
    std::cout << "Encrypted " << msg.size() << " bytes -> " << enc.size() << " bytes\n";
    return 0;
}