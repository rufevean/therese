# therese

![image](https://github.com/user-attachments/assets/4ff8fb58-0e8c-4fdc-b647-ad9d83d1504c)


**Therese** is a lightweight, terminal-based cryptography toolkit that provides classic encryption and decryption utilities. It's designed for learning, experimentation, and practical usage in CTFs or daily terminal workflows.

## Features

Therese currently supports:

- **ROT cipher (ROT13 by default)**: Encode and decode text by rotating alphabetic characters.
- **Caesar cipher brute-force tool**: Try all 26 Caesar shift combinations to help decode unknown ciphers.
- **Clean CLI interface**: Interact via command-line flags or through a text-based UI menu.

Future planned features include:

- Vigenère cipher encoder/decoder
- Base64 encoder/decoder
- Frequency analysis for cracking substitution ciphers
- Interactive help and usage hints

## Usage

You can run `main.py` directly:

```bash
python3 main.py
