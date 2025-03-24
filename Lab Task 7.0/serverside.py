import random
import hashlib
from Crypto.Cipher import AES
import base64

# Diffie-Hellman Key Exchange
def power(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2
    return result

def diffie_hellman():
    """Performs Diffie-Hellman key exchange and returns the shared secret."""
    p = 23 
    g = 5  

    x = random.randint(1, 10)  
    y = random.randint(1, 10)  

    A = power(g, x, p)  
    B = power(g, y, p)  

    shared_secret = power(B, x, p)  
    
    return str(shared_secret) 
# SHA-512 Hash Function
def generate_sha512_hash(text):
    hash_object = hashlib.sha512(text.encode())
    return hash_object.hexdigest()

# AES Encryption
def pad(text):
    """Pads text to make it a multiple of 16 bytes (AES block size)."""
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def aes_encrypt(key, plaintext):
    """Encrypts plaintext using AES CBC mode."""
    key = hashlib.sha256(key.encode()).digest()  
    cipher = AES.new(key, AES.MODE_ECB)  
    encrypted_bytes = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(encrypted_bytes).decode()


def server_send():
    print("Performing Diffie-Hellman Key Exchange...")
    session_key = diffie_hellman()
    print(f"Shared Secret (Session Key): {session_key}")

    
    message = input("Enter the message to send: ")

    
    message_hash = generate_sha512_hash(message)
    print(f"SHA-512 Hash: {message_hash}")

   
    combined_message = message + "||" + message_hash

    
    encrypted_message = aes_encrypt(session_key, combined_message)
    print(f"Encrypted Message: {encrypted_message}")

    
    print("\nSend the following to the client:")
    print(f"Session Key: {session_key}")
    print(f"Encrypted Message: {encrypted_message}")


server_send()
