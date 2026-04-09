// g++ jwt.cpp -lcrypto -lssl -o jwt
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <jwt-cpp/jwt.h>
#include <iostream>

int main() {
    auto token = jwt::create()
        .set_issuer("auth.example.com")
        .set_subject("user123")
        .set_payload_claim("role", jwt::claim(std::string("admin")))
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{1})
        .sign(jwt::algorithm::es256("", "", "-----BEGIN EC PRIVATE KEY-----\nYOUR_KEY_HERE\n-----END EC PRIVATE KEY-----"));

    std::cout << "JWT: " << token << std::endl;
    return 0;
}