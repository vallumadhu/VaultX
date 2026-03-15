from config import DATA_FILE
from utils import generate_key
import os, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import numpy as np

class Decrypter:
    def __init__(self, path, password):
        self.path = path
        self.password = password

        with open(DATA_FILE) as f:
            data = json.load(f)

        found = False
        for _, folder_data in data.items():
            if folder_data["path"] == self.path:

                found = True
                self.salt = bytes.fromhex(folder_data["salt"])
                self.key = generate_key(self.password, self.salt)
                self.aes = AESGCM(self.key)

                if self.check_password(folder_data):

                    for file_name in os.listdir(self.path):
                        full_path = os.path.join(self.path, file_name)

                        if os.path.isfile(full_path) and file_name.endswith(".enc"):
                            self.decrypt(file_name)

                        if os.path.isdir(full_path):
                            Decrypter(full_path, self.password)

                            encoded_foldername = bytes.fromhex(file_name[:-4])
                            encoded_foldername = np.frombuffer(encoded_foldername, dtype=np.uint8).copy()

                            encoded_password = self.password.encode()
                            encoded_password = np.frombuffer(encoded_password, dtype=np.uint8).copy()

                            resized_password = np.resize(encoded_password, encoded_foldername.shape)
                            decrypted_foldername = np.bitwise_xor(encoded_foldername, resized_password)
                            decrypted_foldername_str = decrypted_foldername.tobytes().decode()

                            os.rename(full_path, os.path.join(self.path, decrypted_foldername_str))

                    self.remove_data()
                    break
                else:
                    raise ValueError("Incorrect Password")

        if not found:
            raise ValueError("Cannot decrypt an unencrypted folder")

    def check_password(self, folder_data):
        hash_password = folder_data["hash"]

        h = hashes.Hash(hashes.SHA256())
        h.update(self.key + self.salt)
        return h.finalize().hex() == hash_password

    def decrypt(self, file_name):
        encoded_password = self.password.encode()

        with open(os.path.join(self.path, file_name), "rb") as f:
            file_data = f.read()

        nonce = file_data[:12]
        ciphertext = file_data[12:]

        decrypted_bytes = self.aes.decrypt(nonce, ciphertext, None)

        encoded_filename = bytes.fromhex(file_name[:-4])
        encoded_filename = np.frombuffer(encoded_filename, dtype=np.uint8).copy()
        encoded_password = np.frombuffer(encoded_password, dtype=np.uint8).copy()
        resized_password = np.resize(encoded_password, encoded_filename.shape)

        decrypted_filename = np.bitwise_xor(encoded_filename, resized_password)
        decrypted_filename_str = decrypted_filename.tobytes().decode()

        with open(os.path.join(self.path, file_name), "wb") as f:
            f.write(decrypted_bytes)

        os.rename(os.path.join(self.path, file_name),
                  os.path.join(self.path, decrypted_filename_str))

    def remove_data(self):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)

        data = {k: v for k, v in data.items() if v["path"] != self.path}

        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)