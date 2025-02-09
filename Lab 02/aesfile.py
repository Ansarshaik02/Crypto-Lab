from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)

def encrypt_file(input_filename, output_filename, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_filename, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(input_filename, output_filename, key):
    with open(input_filename, 'rb') as f:
        raw_data = f.read()

    iv = raw_data[:16]
    ciphertext = raw_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_filename, 'wb') as f:
        f.write(plaintext)


sample_filename = "sample.txt"
if not os.path.exists(sample_filename):
    with open(sample_filename, 'w') as f:
        f.write("This is a sample file for encryption and decryption.")


encrypt_file(sample_filename, "encrypted_file.aes", key)
decrypt_file("encrypted_file.aes", "decrypted.txt", key)

print("File encryption and decryption complete.")