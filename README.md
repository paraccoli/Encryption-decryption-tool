# 多言語対応 暗号化/復号化ツール

## 概要
このアプリケーションは、Fernet暗号化とシーザー暗号を使用してメッセージの暗号化と復号化を行うPython製のGUIツールです。ユーザーインターフェースは日本語、英語、中国語に対応しています。

## 特徴
- Fernet暗号化による安全なメッセージの暗号化/復号化
- シーザー暗号によるシンプルな暗号化/復号化
- 日本語、英語、中国語に対応したユーザーインターフェース
- 使いやすいグラフィカルユーザーインターフェース（GUI）

## 必要条件
- Python 3.6以上
- cryptographyライブラリ

## インストール方法
1. このリポジトリをクローンまたはダウンロードします。
2. 必要なライブラリをインストールします：
   ```
   pip install cryptography
   ```

## 使用方法
1. 以下のコマンドでアプリケーションを実行します：
   ```
   python multilingual_encryption_tool.py
   ```
2. GUIウィンドウが開きます。
3. 上部の言語選択メニューから希望の言語を選択します。
4. Fernetタブまたはシーザー暗号タブを選択します。
5. 必要な情報（パスワードやシフト値）を入力し、メッセージを入力します。
6. 「暗号化」または「復号化」ボタンをクリックして操作を実行します。

## 注意事項
- このツールは教育目的で作成されています。重要な情報の暗号化には、より高度なセキュリティ対策を施したツールを使用してください。
- Fernet暗号化では、同じパスワードを使用しないと正しく復号化できません。
- シーザー暗号は簡単に解読される可能性があるため、重要な情報の暗号化には適していません。

---

# Multilingual Encryption/Decryption Tool

## Overview
This application is a Python-based GUI tool for encrypting and decrypting messages using Fernet encryption and Caesar cipher. The user interface supports Japanese, English, and Chinese languages.

## Features
- Secure message encryption/decryption using Fernet encryption
- Simple encryption/decryption using Caesar cipher
- User interface available in Japanese, English, and Chinese
- User-friendly Graphical User Interface (GUI)

## Requirements
- Python 3.6 or higher
- cryptography library

## Installation
1. Clone or download this repository.
2. Install the required library:
   ```
   pip install cryptography
   ```

## Usage
1. Run the application with the following command:
   ```
   python multilingual_encryption_tool.py
   ```
2. The GUI window will open.
3. Select your preferred language from the language selection menu at the top.
4. Choose either the Fernet tab or the Caesar cipher tab.
5. Enter the required information (password or shift value) and input your message.
6. Click the "Encrypt" or "Decrypt" button to perform the operation.

## Notes
- This tool is created for educational purposes. For encrypting sensitive information, use tools with more advanced security measures.
- For Fernet encryption, you must use the same password to correctly decrypt the message.
- Caesar cipher can be easily decrypted and is not suitable for encrypting important information.

## **作成者 Developer**

- 作成者: xM1guel
- GitHub: https://github.com/xM1guel
- Zenn: https://zenn.dev/miguel
