
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

def caesar_bruteforce(cipher):
    print("\nBrute-forcing Caesar Cipher:")
    for r in range(1, 26):
        print(f"Shift {r:2d}: {rot(cipher, r)}")
    print()


def menu():
    while True:
        print("\n==== Crypto CLI Tool ====")
        print("1. ROT Encode")
        print("2. ROT Decode")
        print("3. Caesar Cipher Brute-force")
        print("4. Exit")
        choice = input("Select an option (1-4): ")

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
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    menu()
