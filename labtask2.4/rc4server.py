import socket
from Crypto.Cipher import ARC4

KEYY = b'secretkey'

def decrypt(enc_data):
    cipher = ARC4.new(KEYY)  # Corrected RC4 usage
    dec_data = cipher.decrypt(enc_data)

    with open("decrypted_data.txt", "wb") as f:
        f.write(dec_data)

    print("Decrypted file saved as 'decrypted_data.txt'.")
    print(f"Decrypted data:\n{dec_data.decode(errors='ignore')}")  # Decoding for readable output

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 1212))
    server_socket.listen(1)
    print("Server listening on port 1212...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr} established.")

    # Receive data in chunks to handle large files
    encrypted_data = b""  
    while True:
        chunk = conn.recv(4096)  # Read 4KB at a time
        if not chunk:
            break
        encrypted_data += chunk

    with open('encrypted_file.rc4', 'wb') as f:
        f.write(encrypted_data)
    print("Encrypted file saved as 'encrypted_file.rc4'.")

    decrypt(encrypted_data)

    conn.close()
    server_socket.close()  # Properly close the socket

if __name__ == "__main__":  # Fixed main check
    start_server()
