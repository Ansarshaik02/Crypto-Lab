import hashlib
from Crypto.Cipher import AES
import base64

# AES Decryption
def unpad(text):
    """Removes padding from decrypted text."""
    return text[:-ord(text[-1])]

def aes_decrypt(key, ciphertext):
    """Decrypts AES-encrypted ciphertext."""
    key = hashlib.sha256(key.encode()).digest()  # Ensure 256-bit key
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_bytes.decode())

# SHA-512 Hash Function
def generate_sha512_hash(text):
    hash_object = hashlib.sha512(text.encode())
    return hash_object.hexdigest()

# Simulate Receiving Message
def client_receive(encrypted_message, session_key):
    print("\nReceiving Encrypted Message...")
    print(f"Encrypted Message: {encrypted_message}")

    # Step vi: Decrypt the Message
    decrypted_message = aes_decrypt(session_key, encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")

    # Step vii: Extract original message and hash
    received_message, received_hash = decrypted_message.rsplit("||", 1)

    # Compute new hash
    computed_hash = generate_sha512_hash(received_message)

    # Integrity check
    if received_hash == computed_hash:
        print("Integrity Verified: Message is Authentic ")
    else:
        print("Integrity Check Failed! yth Message may be tampered!")

# Simulating Client-Side Execution
if __name__ == "__main__":
    session_key = input("Enter the shared session key: ")  # Enter same session key from server
    encrypted_message = input("Enter the encrypted message: ")  # Enter encrypted message from server

    client_receive(encrypted_message, session_key)
