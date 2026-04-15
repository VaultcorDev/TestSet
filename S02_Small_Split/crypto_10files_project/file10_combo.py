
import hashlib, base64, secrets

def combo():
    data = secrets.token_bytes(32)
    h = hashlib.sha256(data).digest()
    return base64.b64encode(h)

print(combo())
