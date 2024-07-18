import base64
import hashlib
from cryptography.fernet import Fernet

class EncryptionTool:
    def __init__(self):
        self.key = None
        self.fernet = None

    def generate_key(self, password):
        self.key = hashlib.sha256(password.encode()).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(self.key))

    def encrypt_message(self, message):
        return self.fernet.encrypt(message.encode()).decode()

    def decrypt_message(self, encrypted_message):
        return self.fernet.decrypt(encrypted_message.encode()).decode()

def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            if mode == 'encrypt':
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def main():
    tool = EncryptionTool()

    while True:
        print("\n===== Encryption/Decryption Tool =====")
        print("1. Fernet Encryption/Decryption")
        print("2. Caesar Cipher")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            password = input("Enter a password for key generation: ")
            tool.generate_key(password)
            
            while True:
                print("\n1. Encrypt")
                print("2. Decrypt")
                print("3. Back to main menu")
                sub_choice = input("Enter your choice: ")

                if sub_choice == "1":
                    message = input("Enter the message to encrypt: ")
                    encrypted = tool.encrypt_message(message)
                    print(f"Encrypted message: {encrypted}")
                elif sub_choice == "2":
                    encrypted = input("Enter the message to decrypt: ")
                    try:
                        decrypted = tool.decrypt_message(encrypted)
                        print(f"Decrypted message: {decrypted}")
                    except:
                        print("Decryption failed. Make sure you're using the correct key.")
                elif sub_choice == "3":
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif choice == "2":
            while True:
                print("\n1. Encrypt")
                print("2. Decrypt")
                print("3. Back to main menu")
                sub_choice = input("Enter your choice: ")

                if sub_choice in ["1", "2"]:
                    text = input("Enter the text: ")
                    shift = int(input("Enter the shift value: "))
                    mode = 'encrypt' if sub_choice == "1" else 'decrypt'
                    result = caesar_cipher(text, shift, mode)
                    print(f"Result: {result}")
                elif sub_choice == "3":
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif choice == "3":
            print("Thank you for using the Encryption/Decryption Tool!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
