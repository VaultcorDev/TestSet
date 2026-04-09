// gcc chat.c -lsodium -o chat
#include <sodium.h>
#include <stdio.h>
#include <string.h>

int main() {
    if (sodium_init() < 0) return 1;

    // Alice & Bob generate keys
    unsigned char alice_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char alice_sk[crypto_box_SECRETKEYBYTES];
    unsigned char bob_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(alice_pk, alice_sk);
    crypto_box_keypair(bob_pk, bob_sk);

    // Precompute shared secret
    unsigned char shared[crypto_box_BEFORENMBYTES];
    crypto_box_beforenm(shared, bob_pk, alice_sk);

    // Encrypt message
    const char *msg = "Hello Bob!";
    unsigned char ciphertext[crypto_box_MACBYTES + strlen(msg)];
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    crypto_box_easy_afternm(ciphertext, (unsigned char*)msg, strlen(msg), nonce, shared);

    // Decrypt (Bob side)
    unsigned char decrypted[strlen(msg)];
    if (crypto_box_open_easy_afternm(decrypted, ciphertext, sizeof ciphertext, nonce, shared) == 0) {
        printf("Decrypted: %s\n", decrypted);
    }

    return 0;
}