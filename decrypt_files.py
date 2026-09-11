from pathlib import Path
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
import os

def Find_Directory() ->None:
    root_path = Path("/home/")
    try:
        for path in root_path.rglob("ransomware_test"):
            try:
                if path.is_dir():
                    Find_File(path)
            except PermissionError:
                continue
    except PermissionError:
        print("Permission denied")
    return None

def Find_File(Dir_Path):
    if Dir_Path != None:
        Files = [file for file in Dir_Path.iterdir() if file.is_file()]
        Decrypt_File(Files)
    else:
        print("Somthing went wrong no files found or directory not found")

def Load_Key():
    data = Path("secret.key").read_bytes()
    #nonce = data[32:]
    key = SecretBox(data)
    return key

def Decrypt_File(Files):
    key = Load_Key()
    for file in Files:
        try:
            Encrypted_data = file.read_bytes()
            Original_data = key.decrypt(Encrypted_data)
            file.write_bytes(Original_data)
            print(f"The file {file} has been decrypted")
        except Exception as e:
            print(f"Failed to decrypt the {file} file {e}")

def main():
    Find_Directory()

if __name__ == "__main__":
    main()  