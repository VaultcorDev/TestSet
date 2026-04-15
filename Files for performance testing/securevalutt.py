#!/usr/bin/env python3
# securevault_pro.py
# pip install cryptography pycryptodome tqdm
# chmod +x securevault_pro.py

import os
import sys
import struct
import hashlib
import getpass
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import Camellia, DES
from tqdm import tqdm

# ========================================
# CONFIG & LOGGING
# ========================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)

VAULT_MAGIC = b'SVAULT2\0'
VAULT_VERSION = 200
HEADER_SIZE = 256
WORKERS = os.cpu_count() or 4

# ========================================
# VAULT HEADER STRUCTURE
# ========================================
class VaultHeader:
    def __init__(self):
        self.magic = VAULT_MAGIC
        self.version = VAULT_VERSION
        self.file_count = 0
        self.total_size = 0
        self.master_salt = os.urandom(16)
        self.rsa_pub_hash = b''
        self.camellia_backup = b''
        self.des_fragment = b''
        self.md4_metadata = b''
        self.reserved = b'\x00' * 64

    def pack(self) -> bytes:
        return (
            self.magic +
            struct.pack('<HQQL', self.version, self.file_count, self.total_size, len(self.rsa_pub_hash)) +
            self.master_salt +
            self.rsa_pub_hash +
            self.camellia_backup +
            self.des_fragment +
            self.md4_metadata +
            self.reserved
        )

    @classmethod
    def unpack(cls, data: bytes):
        header = cls()
        offset = 0
        header.magic = data[offset:offset+8]; offset += 8
        header.version, header.file_count, header.total_size, hash_len = struct.unpack_from('<HQQL', data, offset); offset += 20
        header.master_salt = data[offset:offset+16]; offset += 16
        header.rsa_pub_hash = data[offset:offset+hash_len]; offset += hash_len
        # Skip rest for now
        return header

# ========================================
# SECURE VAULT CORE
# ========================================
class SecureVault:
    def __init__(self, vault_path: str, password: str, pub_key_path: str, priv_key_path: str = None):
        self.vault_path = Path(vault_path)
        self.password = password.encode()
        self.pub_key_path = Path(pub_key_path)
        self.priv_key_path = Path(priv_key_path) if priv_key_path else None
        self.master_key = b''
        self.pub_key = None
        self.priv_key = None
        self.header = VaultHeader()
        self.file_entries = []
        self.encrypted_bytes = 0
        self.lock = threading.Lock()

        self._load_keys()
        self._derive_master_key()

    def _load_keys(self):
        try:
            with open(self.pub_key_path, 'rb') as f:
                self.pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            log.info("[RSA] Public key loaded")

            if self.priv_key_path and self.priv_key_path.exists():
                with open(self.priv_key_path, 'rb') as f:
                    self.priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                log.info("[RSA] Private key loaded")
        except Exception as e:
            log.error(f"[KEY] Failed to load keys: {e}")
            sys.exit(1)

        # Hash public key for header
        pub_pem = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.header.rsa_pub_hash = hashlib.sha256(pub_pem).digest()

    def _derive_master_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.header.master_salt,
            iterations=200000,
            backend=default_backend()
        )
        self.master_key = kdf.derive(self.password)
        log.info("[PBKDF2] Master key derived")

    def _encrypt_aes_gcm(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, data, None)
        return aes_key, nonce, ct

    def _encrypt_camellia_backup(self, aes_key: bytes) -> bytes:
        cipher = Camellia.new(self.master_key, Camellia.MODE_ECB)
        padded = aes_key.ljust(32, b'\x00')
        return cipher.encrypt(padded)[:32]

    def _encrypt_des_fragment(self, aes_key: bytes) -> bytes:
        des_key = aes_key[:8].ljust(8, b'\x00')
        cipher = DES.new(des_key, DES.MODE_ECB)
        return cipher.encrypt(aes_key[:8].ljust(8, b'\x00'))

    def _compute_sha256(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _compute_md4(self, data: bytes) -> bytes:
        return hashlib.new('md4', data).digest()

    def _rsa_encrypt_key(self, aes_key: bytes) -> bytes:
        return self.pub_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def _rsa_sign(self, data: bytes) -> bytes:
        if not self.priv_key:
            raise ValueError("Private key required for signing")
        return self.priv_key.sign(
            data,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )

    def _encrypt_file(self, file_path: Path) -> Dict:
        try:
            data = file_path.read_bytes()
            size = len(data)

            # 1. SHA-256
            sha256_hash = self._compute_sha256(data)

            # 2. AES-256-GCM
            aes_key, nonce, ciphertext = self._encrypt_aes_gcm(data)

            # 3. RSA encrypt AES key
            rsa_enc_key = self._rsa_encrypt_key(aes_key)

            # 4. Camellia backup
            cam_backup = self._encrypt_camellia_backup(aes_key)

            # 5. DES fragment
            des_frag = self._encrypt_des_fragment(aes_key)

            # 6. MD4 metadata
            meta = f"{file_path.name}|{size}|{datetime.now().isoformat()}"
            md4_hash = self._compute_md4(meta.encode())

            # 7. Sign (SHA256 + ciphertext)
            to_sign = sha256_hash + ciphertext
            signature = self._rsa_sign(to_sign)

            entry = {
                'path': str(file_path),
                'size': size,
                'sha256': sha256_hash,
                'nonce': nonce,
                'ciphertext': ciphertext,
                'rsa_enc_key': rsa_enc_key,
                'cam_backup': cam_backup,
                'des_frag': des_frag,
                'md4': md4_hash,
                'signature': signature
            }

            with self.lock:
                self.encrypted_bytes += size
                self.file_entries.append(entry)

            log.info(f"[ENCRYPT] {file_path.name} ({size} bytes)")
            return entry

        except Exception as e:
            log.error(f"[ERROR] {file_path}: {e}")
            return None

    def create_vault(self, input_dir: str):
        input_path = Path(input_dir)
        if not input_path.is_dir():
            log.error("Input must be a directory")
            return

        files = [p for p in input_path.rglob('*') if p.is_file() and not p.name.endswith('.vault')]
        if not files:
            log.warning("No files to encrypt")
            return

        log.info(f"[VAULT] Encrypting {len(files)} files from {input_dir}")

        # Write placeholder header
        with open(self.vault_path, 'wb') as f:
            f.write(b'\x00' * HEADER_SIZE)

        # Encrypt with thread pool
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(self._encrypt_file, f) for f in files]
            for _ in tqdm(as_completed(futures), total=len(futures), desc="Encrypting", unit="file"):
                pass

        # Update header
        self.header.file_count = len(self.file_entries)
        self.header.total_size = self.encrypted_bytes

        # Write final vault
        with open(self.vault_path, 'r+b') as f:
            f.seek(0)
            f.write(self.header.pack())

            for entry in self.file_entries:
                path_bytes = entry['path'].encode('utf-8')
                f.write(struct.pack('<Q', len(path_bytes)))
                f.write(path_bytes)
                f.write(struct.pack('<Q', entry['size']))
                f.write(entry['sha256'])
                f.write(entry['nonce'])
                f.write(entry['rsa_enc_key'])
                f.write(entry['cam_backup'])
                f.write(entry['des_frag'])
                f.write(entry['md4'])
                f.write(struct.pack('<Q', len(entry['signature'])))
                f.write(entry['signature'])
                f.write(entry['ciphertext'])

        log.info(f"[DONE] Vault created: {self.vault_path}")
        log.info(f"       Files: {self.header.file_count} | Size: {self.encrypted_bytes // 1024 // 1024} MB")

# ========================================
# KEY GENERATION
# ========================================
def generate_keys():
    log.info("[KEYGEN] Generating RSA 2048-bit key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('vault_priv.pem', 'wb') as f:
        f.write(pem_priv)
    with open('vault_pub.pem', 'wb') as f:
        f.write(pem_pub)

    log.info("[KEYGEN] Keys saved: vault_priv.pem, vault_pub.pem")

# ========================================
# SECURE DELETE
# ========================================
def secure_delete(path: str):
    p = Path(path)
    if not p.exists():
        log.warning(f"[DELETE] Not found: {path}")
        return

    size = p.stat().st_size
    junk = os.urandom(size)
    with open(p, 'r+b') as f:
        f.write(junk)
        f.flush()
        os.fsync(f.fileno())
    p.unlink()
    log.info(f"[DELETE] Securely wiped: {path} ({size} bytes)")

# ========================================
# MAIN CLI
# ========================================
def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                    SECUREVAULT PRO v2.0                  ║
║      Hybrid Crypto: RSA + AES-GCM + Camellia + DES + MD4 ║
╚══════════════════════════════════════════════════════════╝
    """)

def main():
    print_banner()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  securevault_pro.py keygen")
        print("  securevault_pro.py encrypt <input_dir> <output.vault> [priv_key]")
        print("  securevault_pro.py wipe <file>")
        return

    cmd = sys.argv[1]

    if cmd == "keygen":
        generate_keys()

    elif cmd == "encrypt":
        if len(sys.argv) < 4:
            log.error("Missing arguments")
            return
        input_dir = sys.argv[2]
        vault_file = sys.argv[3]
        priv_key = sys.argv[4] if len(sys.argv) > 4 else None

        password = getpass.getpass("Vault Password: ")
        if not password:
            log.error("Password required")
            return

        vault = SecureVault(vault_file, password, "vault_pub.pem", priv_key)
        vault.create_vault(input_dir)

    elif cmd == "wipe":
        if len(sys.argv) < 3:
            log.error("Missing file")
            return
        secure_delete(sys.argv[2])

    else:
        log.error("Unknown command")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.warning("Operation cancelled")
    except Exception as e:
        log.critical(f"Fatal error: {e}")