# therese

![image](https://github.com/user-attachments/assets/4ff8fb58-0e8c-4fdc-b647-ad9d83d1504c)

**Therese** is a lightweight, terminal-based cryptography toolkit that provides classic encryption and decryption utilities. It's designed for learning, experimentation, and practical usage in CTFs or daily terminal workflows.

## Features

Therese currently supports:

- **ROT Cipher (ROT13 by default)**: Encode and decode text by rotating alphabetic characters.
- **Caesar Cipher Brute-force Tool**: Try all 26 Caesar shift combinations to help decode unknown ciphers.
- **Vigenère Cipher**: Encrypt and decrypt text using a keyword.
- **Base64 Encode/Decode**: Convert text to and from Base64 representation.
- **XOR Cipher**: Encrypt or decrypt data using XOR with a key.
- **Atbash Cipher**: A classical cipher that mirrors the alphabet.
- **Hash Generator**: Generate various cryptographic hashes (e.g., MD5, SHA1, SHA256).
- **Regex Extractor**: Extract patterns from text using regular expressions.
- **Rail Fence Cipher**: Encrypt and decrypt using the transposition rail fence technique.
- **RSA Cipher**: Encrypt text with a public key and decrypt using a private key.
- **Clean CLI Interface**: Interact via command-line flags or through a text-based UI menu.

## Usage

You can run `main.py` directly:

```bash
python3 main.py
