# whatsapp_clone.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import Camellia, DES
import hashlib, os

def whatsapp_send(msg, priv_path, pub_path):
    with open(priv_path, 'rb') as f:
        priv = serialization.load_pem_private_key(f.read(), None)
    with open(pub_path, 'rb') as f:
        pub = serialization.load_pem_public_key(f.read())

    # SHA-256
    msg_id = hashes.Hash(hashes.SHA256()); msg_id.update(msg.encode()); msg_id = msg_id.finalize()

    # AES
    aes_key = os.urandom(32); iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor().update(msg.encode().ljust((len(msg)+15)//16*16, b'\0')) + cipher.encryptor().finalize()

    # RSA
    rsa_key = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Camellia
    cam = Camellia.new(aes_key, Camellia.MODE_ECB).encrypt(aes_key)

    # DES
    des = DES.new(aes_key[:8].ljust(8, b'\0'), DES.MODE_ECB).encrypt(aes_key[:8].ljust(8, b'\0'))

    # MD4
    md4 = hashlib.new('md4', msg.encode()).digest()

    # Sign
    sig = priv.sign(hashes.SHA256(), padding.PKCS1v15()).update(msg_id).finalize()

    print("WHATSAPP SEND:")
    print(f"  MSG_ID: {msg_id.hex()}")
    print(f"  RSA_KEY: {rsa_key.hex()}")
    print(f"  CAMELLIA: {cam.hex()}")
    print(f"  DES: {des.hex()}")
    print(f"  MD4: {md4.hex()}")
    print(f"  SIG: {sig.hex()}")
    print(f"  DATA: {enc.hex()}")

whatsapp_send("Secret chat!", "alice_priv.pem", "bob_pub.pem")