from config import DATA_FILE

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets,os,json


def generate_key(password,salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode())


def get_random_salt(bytes_len=16):
    return secrets.token_bytes(bytes_len)


def get_hash_password(password,salt):
    h = hashes.Hash(hashes.SHA256())
    h.update(password+salt)
    return h.finalize().hex()


def check_encrypted(path):
    data = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    
    for _, folder_data in data.items():
            if folder_data["path"] == path:
                return True
    return False