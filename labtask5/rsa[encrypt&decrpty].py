from rsakeygen import generateKeys

def encrypt(m, e, n):
    return pow(m, e, n)  

def decrypt(c, d, n):
    return pow(c, d, n)  

def main():
    e, d, n = generateKeys()
    
    number = 123
    encrypted_num = encrypt(number, e, n)
    decrypted_num = decrypt(encrypted_num, d, n)
    
    print(f"Keys generated:\ne: {e}\nd: {d}\nn: {n}")
    print(f"Number: {number} -> Encrypted: {encrypted_num} -> Decrypted: {decrypted_num}")

    # Encrypt and decrypt an alphabet
    char = 'B'
    ascii_val = ord(char)
    encrypted_char = encrypt(ascii_val, e, n)
    decrypted_char = chr(decrypt(encrypted_char, d, n))
    
    print(f"Alphabet: {char} -> Encrypted: {encrypted_char} -> Decrypted: {decrypted_char}")

if __name__ == "__main__":
    main()
