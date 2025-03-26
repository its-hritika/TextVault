from cryptography.fernet import Fernet
import argparse
import os

KEY_FILE = "secret.key"

def generate_key():
    """Generates and saves a key if not already present."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

def encrypt_text(text, key):
    """Encrypts the given text using Fernet encryption."""
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text.decode()

def decrypt_text(encrypted_text, key):
    """Decrypts the given text using Fernet encryption."""
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(encrypted_text.encode())
    return decrypted_text.decode()

def main():
    parser = argparse.ArgumentParser(description="CLI Text Encryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("text", help="Text to encrypt or decrypt")
    parser.add_argument("--use-key", help="Provide a custom key for encryption and decryption", default=None)
    
    args = parser.parse_args()
    
    if args.use_key:
        key = args.use_key.encode()
        if len(key) != 32:
            print("Error: Custom key must be exactly 32 bytes long.")
            return
    else:
        key = generate_key()
    
    if args.mode == "encrypt":
        result = encrypt_text(args.text, key)
        print(f"Encrypted: {result}")
    elif args.mode == "decrypt":
        try:
            result = decrypt_text(args.text, key)
            print(f"Decrypted: {result}")
        except Exception as e:
            print("Decryption failed. Invalid input or incorrect key.")

if __name__ == "__main__":
    main()
