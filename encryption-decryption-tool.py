import tkinter as tk
from tkinter import ttk, messagebox
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
        try:
            return self.fernet.decrypt(encrypted_message.encode()).decode()
        except:
            return translations[current_language]["decryption_failed"]

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

translations = {
    "en": {
        "title": "Encryption/Decryption Tool",
        "fernet": "Fernet",
        "caesar": "Caesar Cipher",
        "password": "Password:",
        "message": "Message:",
        "encrypt": "Encrypt",
        "decrypt": "Decrypt",
        "result": "Result:",
        "shift": "Shift:",
        "invalid_shift": "Invalid shift value. Please enter an integer.",
        "decryption_failed": "Decryption failed. Make sure you're using the correct key.",
        "language": "Language"
    },
    "ja": {
        "title": "暗号化/復号化ツール",
        "fernet": "Fernet",
        "caesar": "シーザー暗号",
        "password": "パスワード：",
        "message": "メッセージ：",
        "encrypt": "暗号化",
        "decrypt": "復号化",
        "result": "結果：",
        "shift": "シフト：",
        "invalid_shift": "無効なシフト値です。整数を入力してください。",
        "decryption_failed": "復号化に失敗しました。正しいキーを使用していることを確認してください。",
        "language": "言語"
    },
    "zh": {
        "title": "加密/解密工具",
        "fernet": "Fernet",
        "caesar": "凯撒密码",
        "password": "密码：",
        "message": "消息：",
        "encrypt": "加密",
        "decrypt": "解密",
        "result": "结果：",
        "shift": "偏移：",
        "invalid_shift": "无效的偏移值。请输入一个整数。",
        "decryption_failed": "解密失败。请确保您使用的是正确的密钥。",
        "language": "语言"
    }
}

current_language = "en"

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title(translations[current_language]["title"])
        self.master.geometry("500x450")
        
        self.tool = EncryptionTool()
        
        self.create_widgets()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Language selection
        language_frame = ttk.Frame(self.master)
        language_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(language_frame, text=translations[current_language]["language"] + ":").pack(side=tk.LEFT)
        self.language_var = tk.StringVar(value=current_language)
        language_menu = ttk.OptionMenu(language_frame, self.language_var, current_language, "en", "ja", "zh", command=self.change_language)
        language_menu.pack(side=tk.LEFT)

        # Fernet tab
        self.fernet_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.fernet_frame, text=translations[current_language]["fernet"])

        self.fernet_password_label = ttk.Label(self.fernet_frame, text=translations[current_language]["password"])
        self.fernet_password_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.fernet_password = ttk.Entry(self.fernet_frame, show="*")
        self.fernet_password.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        self.fernet_message_label = ttk.Label(self.fernet_frame, text=translations[current_language]["message"])
        self.fernet_message_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.fernet_message = tk.Text(self.fernet_frame, height=5)
        self.fernet_message.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        self.fernet_encrypt_button = ttk.Button(self.fernet_frame, text=translations[current_language]["encrypt"], command=self.fernet_encrypt)
        self.fernet_encrypt_button.grid(row=2, column=0, padx=5, pady=5)
        self.fernet_decrypt_button = ttk.Button(self.fernet_frame, text=translations[current_language]["decrypt"], command=self.fernet_decrypt)
        self.fernet_decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        self.fernet_result_label = ttk.Label(self.fernet_frame, text=translations[current_language]["result"])
        self.fernet_result_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.fernet_result = tk.Text(self.fernet_frame, height=5, state="disabled")
        self.fernet_result.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # Caesar Cipher tab
        self.caesar_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.caesar_frame, text=translations[current_language]["caesar"])

        self.caesar_shift_label = ttk.Label(self.caesar_frame, text=translations[current_language]["shift"])
        self.caesar_shift_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.caesar_shift = ttk.Entry(self.caesar_frame, width=5)
        self.caesar_shift.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        self.caesar_message_label = ttk.Label(self.caesar_frame, text=translations[current_language]["message"])
        self.caesar_message_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.caesar_message = tk.Text(self.caesar_frame, height=5)
        self.caesar_message.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        self.caesar_encrypt_button = ttk.Button(self.caesar_frame, text=translations[current_language]["encrypt"], command=self.caesar_encrypt)
        self.caesar_encrypt_button.grid(row=2, column=0, padx=5, pady=5)
        self.caesar_decrypt_button = ttk.Button(self.caesar_frame, text=translations[current_language]["decrypt"], command=self.caesar_decrypt)
        self.caesar_decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        self.caesar_result_label = ttk.Label(self.caesar_frame, text=translations[current_language]["result"])
        self.caesar_result_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.caesar_result = tk.Text(self.caesar_frame, height=5, state="disabled")
        self.caesar_result.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # Configure grid
        self.fernet_frame.columnconfigure(1, weight=1)
        self.caesar_frame.columnconfigure(1, weight=1)

    def change_language(self, lang):
        global current_language
        current_language = lang
        self.master.title(translations[current_language]["title"])
        self.notebook.tab(0, text=translations[current_language]["fernet"])
        self.notebook.tab(1, text=translations[current_language]["caesar"])
        
        # Update Fernet tab
        self.fernet_password_label.config(text=translations[current_language]["password"])
        self.fernet_message_label.config(text=translations[current_language]["message"])
        self.fernet_encrypt_button.config(text=translations[current_language]["encrypt"])
        self.fernet_decrypt_button.config(text=translations[current_language]["decrypt"])
        self.fernet_result_label.config(text=translations[current_language]["result"])
        
        # Update Caesar tab
        self.caesar_shift_label.config(text=translations[current_language]["shift"])
        self.caesar_message_label.config(text=translations[current_language]["message"])
        self.caesar_encrypt_button.config(text=translations[current_language]["encrypt"])
        self.caesar_decrypt_button.config(text=translations[current_language]["decrypt"])
        self.caesar_result_label.config(text=translations[current_language]["result"])

    def fernet_encrypt(self):
        password = self.fernet_password.get()
        message = self.fernet_message.get("1.0", tk.END).strip()
        self.tool.generate_key(password)
        encrypted = self.tool.encrypt_message(message)
        self.update_result(self.fernet_result, encrypted)

    def fernet_decrypt(self):
        password = self.fernet_password.get()
        message = self.fernet_message.get("1.0", tk.END).strip()
        self.tool.generate_key(password)
        decrypted = self.tool.decrypt_message(message)
        self.update_result(self.fernet_result, decrypted)

    def caesar_encrypt(self):
        try:
            shift = int(self.caesar_shift.get())
            message = self.caesar_message.get("1.0", tk.END).strip()
            encrypted = caesar_cipher(message, shift, 'encrypt')
            self.update_result(self.caesar_result, encrypted)
        except ValueError:
            messagebox.showerror("Error", translations[current_language]["invalid_shift"])

    def caesar_decrypt(self):
        try:
            shift = int(self.caesar_shift.get())
            message = self.caesar_message.get("1.0", tk.END).strip()
            decrypted = caesar_cipher(message, shift, 'decrypt')
            self.update_result(self.caesar_result, decrypted)
        except ValueError:
            messagebox.showerror("Error", translations[current_language]["invalid_shift"])

    def update_result(self, text_widget, result):
        text_widget.config(state="normal")
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, result)
        text_widget.config(state="disabled")

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
