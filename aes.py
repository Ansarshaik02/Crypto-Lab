from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

key = os.urandom(16)

def encrypt_text(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_text(encrypted_text, key):
    raw_data = base64.b64decode(encrypted_text)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# Example Usage
plaintext = "Hello, AES Encryption!"
encrypted = encrypt_text(plaintext, key)
decrypted = decrypt_text(encrypted, key)

print(f"Original Text: {plaintext}")
print(f"Encrypted Text: {encrypted}")
print(f"Decrypted Text: {decrypted}")
