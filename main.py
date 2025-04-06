import base64

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

def base64_encode(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decode(text):
    return base64.b64decode(text.encode('utf-8')).decode('utf-8')

def rot_encoder(cipher, r=13):
    return rot(cipher, r)

def rot_decoder(cipher, r=13):
    return rot(cipher, -r)

def caesar_bruteforce(cipher):
    print("\nBrute-forcing Caesar Cipher:")
    for r in range(1, 26):
        print(f"Shift {r:2d}: {rot(cipher, r)}")
    print()


def menu():
    show_banner()
    while True:
        print("1. ROT Encode")
        print("2. ROT Decode")
        print("3. Caesar Cipher Brute-force")
        print("4. Base64 Encode")
        print("5. Base64 Decode")
        print("6. Exit")
        choice = input("Select an option (1-6): ")

        if choice == "1":
            text = input("Enter text to encode: ")
            try:
                r = int(input("Enter rotation value (default 13): ") or "13")
                print("Encoded:", rot_encoder(text, r))
            except ValueError:
                print("Invalid rotation value.")
        elif choice == "2":
            text = input("Enter text to decode: ")
            try:
                r = int(input("Enter rotation value used in encryption (default 13): ") or "13")
                print("Decoded:", rot_decoder(text, r))
            except ValueError:
                print("Invalid rotation value.")
        elif choice == "3":
            cipher = input("Enter cipher text to brute-force: ")
            caesar_bruteforce(cipher)
        elif choice == "4":
            text = input("Enter text to Base64 encode: ")
            print("Base64 Encoded:", base64_encode(text))
        elif choice == "5":
            text = input("Enter Base64 text to decode: ")
            try:
                print("Base64 Decoded:", base64_decode(text))
            except Exception as e:
                print("Decoding failed:", e)
        elif choice == "6":
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    menu()
