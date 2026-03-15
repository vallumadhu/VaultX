import json, os
from config import DATA_FILE
from encrypter import Encrypter
from decrypter import Decrypter
from utils import check_encrypted

if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump({}, f)

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
            except ValueError as e:
                print(f"\n  ✗  {e}\n")
            except Exception as e:
                print(f"\n  ✗  Error: {e}\n")

        elif choice == "2":
            print()
            path = input("  Folder path   : ").strip()
            if not os.path.isdir(path):
                print("\n  ✗  Folder not found.\n")
                continue
            if not check_encrypted(path):
                print("\n  ✗  Folder is not encrypted.\n")
                continue
            password = input("  Password       : ").strip()
            if not password:
                print("\n  ✗  Password cannot be empty.\n")
                continue
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