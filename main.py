import base64
import hashlib
import re
import pyperclip

# Banner

def show_banner():
    banner = r"""
  __  .__                                        
_/  |_|  |__   ___________   ____   ______ ____  
\   __\  |  \_/ __ \_  __ \_/ __ \ /  ___// __ \ 
 |  | |   Y  \  ___/|  | \/\  ___/ \___ \\  ___/ 
 |__| |___|  /\___  >__|    \___  >____  >\___  >
           \/     \/            \/     \/     \/ 
                                        
       🕵️‍♀️ Therese 
    """
    print(banner)

# ROT

def rot(cipher, r=13):
    result = []
    for char in cipher:
        if 'a' <= char <= 'z':
            rotated = chr((ord(char) - ord('a') + r) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            rotated = chr((ord(char) - ord('A') + r) % 26 + ord('A'))
        else:
            rotated = char
        result.append(rotated)
    return ''.join(result)

def rot_encoder(cipher, r=13):
    return rot(cipher, r)

def rot_decoder(cipher, r=13):
    return rot(cipher, -r)

# Caesar Brute Force

def caesar_bruteforce(cipher):
    print("\nBrute-forcing Caesar Cipher:")
    for r in range(1, 26):
        print(f"Shift {r:2d}: {rot(cipher, r)}")
    print()

# Base64

def base64_encode(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decode(text):
    return base64.b64decode(text.encode('utf-8')).decode('utf-8')

# Vigenère

def vigenere_encrypt(plaintext, key):
    result = []
    key = key.lower()
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            if char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(ciphertext, key):
    result = []
    key = key.lower()
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            if char.islower():
                result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            else:
                result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

# XOR

def xor_cipher(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

# Atbash

def atbash_cipher(text):
    result = []
    for char in text:
        if char.islower():
            result.append(chr(ord('z') - (ord(char) - ord('a'))))
        elif char.isupper():
            result.append(chr(ord('Z') - (ord(char) - ord('A'))))
        else:
            result.append(char)
    return ''.join(result)

# Hashing

def hash_generator(text):
    print("SHA256:", hashlib.sha256(text.encode()).hexdigest())
    print("SHA1  :", hashlib.sha1(text.encode()).hexdigest())
    print("MD5   :", hashlib.md5(text.encode()).hexdigest())

# Regex

def regex_extractor(text, pattern):
    matches = re.findall(pattern, text)
    print("Matches:", matches)

# Rail Fence Cipher

def rail_fence_encrypt(text, rails):
    fence = [['' for _ in text] for _ in range(rails)]
    rail = 0
    var = 1

    for i, char in enumerate(text):
        fence[rail][i] = char
        rail += var
        if rail == 0 or rail == rails - 1:
            var = -var

    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(cipher, rails):
    fence = [['' for _ in cipher] for _ in range(rails)]
    rail = 0
    var = 1

    for i in range(len(cipher)):
        fence[rail][i] = '*'
        rail += var
        if rail == 0 or rail == rails - 1:
            var = -var

    idx = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] == '*' and idx < len(cipher):
                fence[r][c] = cipher[idx]
                idx += 1

    result = []
    rail = 0
    var = 1
    for i in range(len(cipher)):
        result.append(fence[rail][i])
        rail += var
        if rail == 0 or rail == rails - 1:
            var = -var

    return ''.join(result)

# Menu
def rsa_decrypt(c, d, n):
    try:
        decrypted = pow(c, d, n)
        message = ''
        while decrypted > 0:
            message = chr(decrypted % 256) + message
            decrypted //= 256
        return message
    except Exception as e:
        return f"Decryption failed: {e}"


def copy_to_clipboard(result):
    pyperclip.copy(result)
    print("\nCopied to clipboard!\n")


def menu():
    show_banner()
    while True:
        print("1. ROT Cipher")
        print("2. Caesar Cipher Brute-force")
        print("3. Base64")
        print("4. Vigenère Cipher")
        print("5. XOR Cipher")
        print("6. Atbash Cipher")
        print("7. Hash Generator")
        print("8. Regex Extractor")
        print("9. Rail Fence Cipher")
        print("10. RSA Decryption")
        print("11. Exit")

        choice = input("Select an option (1-11): ")

        if choice == "1":
            rot_choice = input("a) Encode\nb) Decode\nChoose (a/b): ").lower()
            text = input("Enter text: ")
            try:
                r = int(input("Enter rotation value (default 13): ") or "13")
                result = rot_encoder(text, r) if rot_choice == 'a' else rot_decoder(text, r)
                print("Result:", result)
                copy_to_clipboard(result)
            except ValueError:
                print("Invalid rotation value.")

        elif choice == "2":
            text = input("Enter cipher text to brute-force: ")
            caesar_bruteforce(text)

        elif choice == "3":
            sub = input("a) Encode\nb) Decode\nChoose (a/b): ").lower()
            text = input("Enter text: ")
            try:
                result = base64_encode(text) if sub == 'a' else base64_decode(text)
                print("Result:", result)
                copy_to_clipboard(result)
            except Exception as e:
                print("Error:", e)

        elif choice == "4":
            sub = input("a) Encrypt\nb) Decrypt\nChoose (a/b): ").lower()
            text = input("Enter text: ")
            key = input("Enter key: ")
            result = vigenere_encrypt(text, key) if sub == 'a' else vigenere_decrypt(text, key)
            print("Result:", result)
            copy_to_clipboard(result)

        elif choice == "5":
            text = input("Enter text: ")
            key = input("Enter XOR key: ")
            result = xor_cipher(text, key)
            print("Ciphered:", result)
            copy_to_clipboard(result)

        elif choice == "6":
            text = input("Enter text: ")
            result = atbash_cipher(text)
            print("Ciphered:", result)
            copy_to_clipboard(result)

        elif choice == "7":
            text = input("Enter text to hash: ")
            hash_generator(text)

        elif choice == "8":
            text = input("Enter text: ")
            pattern = input("Enter regex pattern: ")
            regex_extractor(text, pattern)

        elif choice == "9":
            sub = input("a) Encrypt\nb) Decrypt\nChoose (a/b): ").lower()
            text = input("Enter text: ")
            try:
                rails = int(input("Enter number of rails: "))
                result = rail_fence_encrypt(text, rails) if sub == 'a' else rail_fence_decrypt(text, rails)
                print("Result:", result)
                copy_to_clipboard(result)
            except ValueError:
                print("Invalid number of rails.")

        elif choice == "10":
            try:
                c = int(input("Enter ciphertext (as integer): "))
                d = int(input("Enter private exponent (d): "))
                n = int(input("Enter modulus (n): "))
                result = rsa_decrypt(c, d, n)
                print("Decrypted message:", result)
                copy_to_clipboard(result)
            except ValueError:
                print("Invalid RSA input.")

        elif choice == "11":
            print("Exiting... Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    menu()
