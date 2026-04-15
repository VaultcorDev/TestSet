from cryptography.hazmat.primitives import hashes, AES
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import modes
import falcon

class Wallet:
    def __init__(self):
        self.password = None
        self.private_key = None
        self.public_key = None

    def generate_falcon_key_pair(self):
        self.private_key = falcon.generate_private_key(key_size = 512)
        self.public_key = self.private_key.public_key()

    def encrypt_aes_transaction(self, transaction_data):
        if self.password is None:
            raise ValueError("Password is not set. Cannot encrypt data.")

        cipher = AES.aes256.encrypt(self.password.encode(), modes.ECB())     
        encrypted_data = cipher.update(transaction_data) + cipher.finalize()
        return encrypted_data

    def decrypt_aes_transaction(self, encrypted_data):
        if self.password is None:
            raise ValueError("Password is not set. Cannot decrypt data.")

        cipher = AES.aes256.decrypt(self.password.encode(), modes.ECB())
        decrypted_data = cipher.update(encrypted_data) + cipher.finalize()
        return decrypted_data

    def falcon_sign_transaction(self, transaction_data):
        if self.private_key is None:
            raise ValueError("Private key is not set. Cannot sign transaction.")

        signature = self.private_key.sign(
            transaction_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return signature

    def falcon_verify_transaction(self, transaction_data, signature, public_key):
        public_key.verify(
            signature,
            transaction_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )


# Example usage:
wallet = Wallet()

# Generate RSA key pair
wallet.generate_falcon_key_pair("seed")

# Set password for AES encryption/decryption
wallet.password = "my_password"

# Encrypt data using AES
encrypted_data = wallet.encrypt_aes_transaction("Hello, World!".encode())
print(f"Encrypted data: {encrypted_data}")

# Decrypt transaction data using AES
decrypted_data = wallet.decrypt_aes_transaction(encrypted_data)
print(f"Decrypted data: {decrypted_data.decode()}")

# Sign transaction
transaction_data = b"Transaction data"
signature = wallet.falcon_sign_transaction(transaction_data)

# Verify transaction
wallet.falcon_verify_transaction(transaction_data, signature, wallet.public_key)
