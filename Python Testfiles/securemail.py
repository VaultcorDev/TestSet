# smime_email.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import hashlib
import base64

def smime_sign_encrypt(msg: str, priv_key_path: str, pub_key_path: str, output_file: str):
    # Load keys
    with open(priv_key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_key_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    # 1. SHA-256
    sha256_hash = hashes.Hash(hashes.SHA256())
    sha256_hash.update(msg.encode())
    sha256_digest = sha256_hash.finalize()

    # 2. MD4 (via hashlib)
    md4_hash = hashlib.new('md4', msg.encode()).digest()

    # 3. AES-256-CBC
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(msg.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    enc_msg = encryptor.update(padded) + encryptor.finalize()

    # 4. RSA encrypt AES key
    rsa_enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 5. Camellia (via pycryptodome)
    from Crypto.Cipher import Camellia
    cam_cipher = Camellia.new(aes_key, Camellia.MODE_ECB)
    cam_enc_key = cam_cipher.encrypt(aes_key)

    # 6. DES (legacy)
    from Crypto.Cipher import DES
    des_key = aes_key[:8].ljust(8, b'\0')
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    des_enc = des_cipher.encrypt(aes_key[:8].ljust(8, b'\0'))

    # 7. RSA sign
    signature = priv.sign(sha256_digest, padding.PKCS1v15(), hashes.SHA256())

    # Save
    with open(output_file, "w") as f:
        f.write("-----BEGIN SMIME-----\n")
        f.write(f"SHA256: {sha256_digest.hex()}\n")
        f.write(f"MD4: {md4_hash.hex()}\n")
        f.write(f"IV: {iv.hex()}\n")
        f.write(f"RSA_KEY: {rsa_enc_key.hex()}\n")
        f.write(f"CAMELLIA_KEY: {cam_enc_key.hex()}\n")
        f.write(f"DES_KEY: {des_enc.hex()}\n")
        f.write(f"SIGNATURE: {signature.hex()}\n")
        f.write(f"DATA: {enc_msg.hex()}\n")
        f.write("-----END SMIME-----\n")
    print("[S/MIME] Email signed & encrypted")

# Run
if __name__ == "__main__":
    smime_sign_encrypt("Project X launches!", "alice_priv.pem", "bob_pub.pem", "email.smime")