import socket
import random
from Crypto.Util import number

def main():
    host = 'localhost'
    port = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server is listening on port", port)

    client_socket, addr = server_socket.accept()
    print("Client connected:", addr)

    g = 23  # Primitive root
    n = 563  # Prime number

    # Private key of server
    y = number.getRandomNBitInteger(1024)

    # Receiving client's public key (K1)
    K1 = int(client_socket.recv(1024).decode())
    print("Public K1 received from Client:", K1)

    # Calculating server's public key (K2)
    K2 = pow(g, y, n)

    # Sending server's public key (K2) to client
    client_socket.send(str(K2).encode())
    print("Public K2 sent to Client:", K2)

    # Calculating shared secret key
    Key = pow(K1, y, n)
    print("Shared Secret Key (Server):", Key)

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
