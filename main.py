import secrets,json,os,sys
import numpy as np
from cryptography.hazmat.primitives import hashes

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
DATA_FILE = os.path.join(BASE_DIR, "data.txt")

class Encrypter:
    def __init__(self,path,password):
        self.path = path
        self.password = password

        self.store_data()
        file_paths = os.listdir(self.path)

        for file_path in file_paths:
            if os.path.isfile(os.path.join(self.path,file_path)):
                self.encrypt(file_path)

            if os.path.isdir(os.path.join(self.path,file_path)):
                #encrypting folder name
                encoded_foldername = file_path.encode()
                encoded_foldername = np.frombuffer(encoded_foldername,dtype=np.uint8)

                encoded_password = self.password.encode()
                encoded_password = np.frombuffer(encoded_password, dtype=np.uint8)

                resized_password = np.resize(encoded_password,encoded_foldername.shape)

                encrypted_foldername = np.bitwise_xor(encoded_foldername,resized_password)
                encrypted_foldername_hex = encrypted_foldername.tobytes().hex()

                os.rename(os.path.join(self.path,file_path), os.path.join(self.path,encrypted_foldername_hex))

                e = Encrypter(os.path.join(self.path,encrypted_foldername_hex),self.password)
    
    def get_random_salt(self,bytes_len=16):
        return secrets.token_hex(bytes_len)

    def get_hash_password(self):
        salt = self.get_random_salt()

        h = hashes.Hash(hashes.SHA256())
        h.update(self.password.encode()+salt.encode())

        return h.finalize().hex(),salt
    
    def store_data(self):
        data = {}
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

        hash_password, salt = self.get_hash_password()
        record_id = str(len(data))

        data[record_id] = {
            "path": self.path,
            "hash": hash_password,
            "salt": salt
        }

        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)
    
    def encrypt(self,file_name):
        encoded_password = self.password.encode()

        file_data = None
        with open(os.path.join(self.path,file_name),"rb") as f:
            file_data = f.read()
        
        #encrypting data
        encoded_password = np.frombuffer(encoded_password,dtype=np.uint8)
        file_data = np.frombuffer(file_data,dtype=np.uint8)

        resized_password = np.resize(encoded_password,file_data.shape)

        encrypted_data = np.bitwise_xor(file_data,resized_password)
        encrypted_bytes = encrypted_data.tobytes()

        #encrypting file name
        encoded_filename = file_name.encode()
        encoded_filename = np.frombuffer(encoded_filename,dtype=np.uint8)
        resized_password = np.resize(encoded_password,encoded_filename.shape)

        encrypted_filename = np.bitwise_xor(encoded_filename,resized_password)
        encrypted_filename_hex = encrypted_filename.tobytes().hex()

        with open(os.path.join(self.path,file_name),"wb") as f:
            f.write(encrypted_bytes)
        
        os.rename(os.path.join(self.path,file_name),os.path.join(self.path,encrypted_filename_hex))

class Decrypter:
    def __init__(self,path,password):
        self.path = path
        self.password = password
        data = None
        with open(DATA_FILE) as f:
            data = json.load(f)

        found = False
        for _, folder_data in data.items():
            if folder_data["path"] == self.path:
                found = True
                if self.check_password(folder_data):
                    for file_name in os.listdir(self.path):
                        if os.path.isfile(os.path.join(self.path,file_name)):
                            self.decrypt(file_name)
                        if os.path.isdir(os.path.join(self.path,file_name)):
                            d = Decrypter(os.path.join(self.path,file_name),self.password)

                            #decrypting folder name
                            encoded_foldername = bytes.fromhex(file_name)
                            encoded_foldername = np.frombuffer(encoded_foldername, dtype=np.uint8)

                            encoded_password = self.password.encode()
                            encoded_password = np.frombuffer(encoded_password, dtype=np.uint8)

                            resized_password = np.resize(encoded_password,encoded_foldername.shape)

                            decrypted_foldername = np.bitwise_xor(encoded_foldername,resized_password)
                            decrypted_foldername_hex = decrypted_foldername.tobytes().decode()

                            os.rename(os.path.join(self.path,file_name), os.path.join(self.path,decrypted_foldername_hex))
                            
                    self.remove_data()
                    break
                else:
                    raise ValueError("Incorrect Password")

        if not found:
            raise ValueError("Cannot decrypt an unencrypted folder")
    
    def check_password(self,folder_data):
        salt = folder_data["salt"]
        hash_password = folder_data["hash"]

        h = hashes.Hash(hashes.SHA256())
        h.update(self.password.encode()+salt.encode())
        return h.finalize().hex() == hash_password
    
    def decrypt(self,file_name):

        encoded_password = self.password.encode()

        file_data = None
        with open(os.path.join(self.path,file_name),"rb") as f:
            file_data = f.read()
        
        #decrypting data
        encoded_password = np.frombuffer(encoded_password,dtype=np.uint8)
        file_data = np.frombuffer(file_data,dtype=np.uint8)

        resized_password = np.resize(encoded_password,file_data.shape)

        decrypted_data = np.bitwise_xor(file_data,resized_password)
        decrypted_bytes = decrypted_data.tobytes()

        #decrypting file name
        encoded_filename = bytes.fromhex(file_name)
        encoded_filename = np.frombuffer(encoded_filename,dtype=np.uint8)
        resized_password = np.resize(encoded_password,encoded_filename.shape)

        decrypted_filename = np.bitwise_xor(encoded_filename,resized_password)
        decrypted_filename_hex = decrypted_filename.tobytes().decode()

        with open(os.path.join(self.path,file_name),"wb") as f:
            f.write(decrypted_bytes)
        
        os.rename(os.path.join(self.path,file_name),os.path.join(self.path,decrypted_filename_hex))

    def remove_data(self):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)

        data = {k: v for k, v in data.items() if v["path"] != self.path}

        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)

if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump({}, f)

#CLI
def main():
    print("\n╔══════════════════════════════╗")
    print("║         V A U L T X          ║")
    print("╚══════════════════════════════╝\n")

    while True:
        print("  [1]  Encrypt a folder")
        print("  [2]  Decrypt a folder")
        print("  [0]  Exit\n")

        choice = input("  > ").strip()

        if choice == "1":
            print()
            path = input("  Folder path   : ").strip()
            if not os.path.isdir(path):
                print("\n  ✗  Folder not found.\n")
                continue
            password = input("  Password       : ").strip()
            if not password:
                print("\n  ✗  Password cannot be empty.\n")
                continue
            try:
                print("\n  Encrypting...")
                Encrypter(path, password)
                print("  ✓  Done.\n")
            except Exception as e:
                print(f"\n  ✗  Error: {e}\n")

        elif choice == "2":
            print()
            path = input("  Folder path   : ").strip()
            if not os.path.isdir(path):
                print("\n  ✗  Folder not found.\n")
                continue
            password = input("  Password       : ").strip()
            try:
                print("\n  Decrypting...")
                Decrypter(path, password)
                print("  ✓  Done.\n")
            except ValueError as e:
                print(f"\n  ✗  {e}\n")
            except Exception as e:
                print(f"\n  ✗  Error: {e}\n")

        elif choice == "0":
            print("\n  Goodbye.\n")
            break

        else:
            print("\n  Invalid option. Try again.\n")


if __name__ == "__main__":
    main()