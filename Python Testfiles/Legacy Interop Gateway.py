# gateway.py
import os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import Camellia, DES

def bridge(data):
    sha = hashlib.sha256(data).digest()
    md4 = hashlib.new('md4', data).digest()
    aes_key = os.urandom(32); iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor().update(data.ljust((len(data)+15)//16*16, b'\0')) + cipher.encryptor().finalize()

    des = DES.new(aes_key[:8].ljust(8, b'\0'), DES.MODE_ECB).encrypt(aes_key[:8].ljust(8, b'\0'))
    cam = Camellia.new(aes_key, Camellia.MODE_ECB).encrypt(aes_key)

    return sha + md4 + iv + des + cam + enc