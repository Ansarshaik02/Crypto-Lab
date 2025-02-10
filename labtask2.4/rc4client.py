import socket
from Crypto.Cipher import ARC4

KEYY = b'secretkey'

def encrypt(file):
    try:
        with open(file, "rb") as filee:
            f_data = filee.read()
    except FileNotFoundError:
        print(f"Error: The file '{file}' was not found.")
        return None

    cipher = ARC4.new(KEYY)  # Corrected RC4 usage
    enc_data = cipher.encrypt(f_data)
    return enc_data

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect(('localhost', 1212))
    except ConnectionRefusedError:
        print("Error: Could not connect to the server. Make sure the server is running.")
        return

    encrypted_message = encrypt("Text_input.txt")
    
    if encrypted_message:  # Send only if encryption was successful
        client_socket.sendall(encrypted_message)  # Use sendall to ensure complete data transfer
        print("File sent to server successfully.")

    client_socket.close()

if __name__ == "__main__":  # Fixed main check
    start_client()
