# Crypto-Lab
Server:                          Client:
1. Generate AES Key              1. Connect to Server
2. Send Key to Client            2. Receive AES Key
3. Wait for Encrypted Message    3. Encrypt Message
4. Decrypt Message               4. Send Encrypted Message
5. Encrypt Response              5. Wait for Encrypted Response
6. Send Encrypted Response       6. Decrypt Response
7. Repeat                        7. Repeat
8. Shutdown                      8. Shutdown


Key Points

AES Encryption:
Uses AES in CBC mode with a 128-bit key.
Each message is padded to match the AES block size (16 bytes).
The initialization vector (IV) is prepended to the ciphertext for secure decryption.

Key Exchange:
The server generates the AES key and shares it with the client (insecure in this example; use a secure key exchange protocol like Diffie-Hellman in production).

Communication Flow:
Client and server take turns sending encrypted messages.
Each message is encrypted before sending and decrypted after receiving.