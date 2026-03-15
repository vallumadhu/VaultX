from utils import get_random_salt,generate_key,check_encrypted,get_hash_password
from config import DATA_FILE

import numpy as np
import os,json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

class Encrypter:
    def __init__(self,path,password):
        self.path = path
        self.password = password

        file_paths = os.listdir(self.path)

        isEncryptedFolder = check_encrypted(self.path)
        if isEncryptedFolder:
            with open(DATA_FILE) as f:
                data = json.load(f)
            
            folder_data = None
            for _, fd in data.items():
                if fd["path"] == self.path:
                    folder_data = fd
                    self.salt = bytes.fromhex(folder_data["salt"])
                    self.key = generate_key(password,self.salt)
                    self.aes = AESGCM(self.key)
                    break
            
            if not self.check_password(folder_data):
                raise ValueError("Incorrect Password")
        else:
            self.salt = get_random_salt()
            self.key = generate_key(password,self.salt)
            self.aes  = AESGCM(self.key)
            self.store_data()
  

        for file_path in file_paths:
            alreadyEncrypted = self.isFileEncrypted(file_path,isEncryptedFolder)
            if os.path.isfile(os.path.join(self.path,file_path)) and not alreadyEncrypted:
                self.encrypt(file_path)

            if os.path.isdir(os.path.join(self.path,file_path)) and not alreadyEncrypted:
                #encrypting folder name
                encoded_foldername = file_path.encode()
                encoded_foldername = np.frombuffer(encoded_foldername,dtype=np.uint8).copy()

                encoded_password = self.password.encode()
                encoded_password = np.frombuffer(encoded_password, dtype=np.uint8).copy()

                resized_password = np.resize(encoded_password,encoded_foldername.shape)

                encrypted_foldername = np.bitwise_xor(encoded_foldername,resized_password)
                encrypted_foldername_hex = encrypted_foldername.tobytes().hex()

                encrypted_foldername_hex += ".enc"

                os.rename(os.path.join(self.path,file_path), os.path.join(self.path,encrypted_foldername_hex))

                e = Encrypter(os.path.join(self.path,encrypted_foldername_hex),self.password)

    
    def isFileEncrypted(self,file_path,isEncryptedFolder):
        if not isEncryptedFolder:
            return False
        
        return file_path.endswith(".enc")
    
    def check_password(self, folder_data):
        hash_password = folder_data["hash"]

        h = hashes.Hash(hashes.SHA256())
        h.update(self.key + self.salt)
        return h.finalize().hex() == hash_password
    
    def store_data(self):
        data = {}
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

        hash_password = get_hash_password(self.key,self.salt)
        record_id = str(len(data))

        data[record_id] = {
            "path": self.path,
            "hash": hash_password,
            "salt": self.salt.hex()
        }

        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)
        
    
    def encrypt(self, file_name):
        encoded_password = self.password.encode()
        encoded_password = np.frombuffer(encoded_password, dtype=np.uint8).copy()

        file_path = os.path.join(self.path, file_name)
        CHUNK_SIZE = 512 * 1024 * 1024

        encrypted_chunks = []
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_nonce = os.urandom(12)
                encrypted_chunk = self.aes.encrypt(chunk_nonce, chunk, None)
                encrypted_chunks.append(chunk_nonce + len(encrypted_chunk).to_bytes(8, 'big') + encrypted_chunk)

        encoded_filename = file_name.encode()
        encoded_filename = np.frombuffer(encoded_filename, dtype=np.uint8).copy()
        resized_password = np.resize(encoded_password, encoded_filename.shape)
        encrypted_filename = np.bitwise_xor(encoded_filename, resized_password)
        encrypted_filename_hex = encrypted_filename.tobytes().hex() + ".enc"

        with open(file_path, "wb") as f:
            f.write(len(encrypted_chunks).to_bytes(4, 'big'))
            for chunk in encrypted_chunks:
                f.write(chunk)

        os.rename(file_path, os.path.join(self.path, encrypted_filename_hex))