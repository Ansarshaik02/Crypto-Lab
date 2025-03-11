import socket
import random
from Cryptodome.Util import number


def main():
    host = 'localhost'
    port = 5000

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Connected to the server.")

    g = 23  # Primitive root
    n = 563  # Prime number

    # Private key of client
    x = number.getRandomNBitInteger(1024)

    # Calculating client's public key (K1)
    K1 = pow(g, x, n)
    client_socket.send(str(K1).encode())
    print("Public K1 sent to Server:", K1)

    # Receiving server's public key (K2)
    K2 = int(client_socket.recv(1024).decode())
    print("Public K2 received from Server:", K2)

    # Calculating shared secret key
    Key = pow(K2, x, n)
    print("Shared Secret Key (Client):", Key)

    client_socket.close()

if __name__ == "__main__":
    main()
