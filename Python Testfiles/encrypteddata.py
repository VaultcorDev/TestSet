# backup.py
import os, hashlib, struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import Camellia, DES

def backup_file(path, pub_key_path, archive):
    with open(path, "rb") as f:
        data = f.read()

    # SHA-256
    sha256 = hashlib.sha256(data).digest()

    # MD4
    md4 = hashlib.new('md4', data).digest()

    # AES-256
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    enc = encryptor.update(data + bytes([pad_len]*pad_len)) + encryptor.finalize()

    # Load pub key
    with open(pub_key_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    # RSA
    rsa_enc = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Camellia
    cam = Camellia.new(aes_key, Camellia.MODE_ECB).encrypt(aes_key)

    # DES
    des = DES.new(aes_key[:8].ljust(8, b'\0'), DES.MODE_ECB).encrypt(aes_key[:8].ljust(8, b'\0'))

    # Write
    archive.write(path.encode() + b'\0')
    archive.write(struct.pack("<Q", len(data)))
    archive.write(sha256 + md4 + iv + struct.pack("<H", len(rsa_enc)) + rsa_enc + cam + des + enc)
    print(f"[BACKUP] {path}")

if __name__ == "__main__":
    with open("backup.enc", "wb") as arch:
        for f in os.listdir("."):
            if f.endswith(".txt"):
                backup_file(f, "backup_pub.pem", arch)