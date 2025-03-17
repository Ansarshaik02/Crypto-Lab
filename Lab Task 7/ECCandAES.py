import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# secp256k1 Curve Parameters
P1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Prime field
A1 = 0  # Curve parameter a
B1 = 7  # Curve parameter b
Gx1 = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy1 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Order of the curve

# secp192r1 Curve Parameters
P2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF  # Prime field
A2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
B2 = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
Gx2 = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy2 = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
N2 = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831  # Order of the curve

def inverse_mod(k, p):
    """Computes the modular inverse of k modulo p."""
    return pow(k, -1, p)

def point_addition(P1, P2, A, P):
    """Adds two points P1 and P2 on the elliptic curve."""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    
    if x1 == x2 and y1 != y2:
        return None
    
    if P1 == P2:
        m = (3 * x1 * x1 + A) * inverse_mod(2 * y1, P) % P
    else:
        m = (y2 - y1) * inverse_mod(x2 - x1, P) % P
    
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_multiplication(k, P, A, Pmod):
    """Performs scalar multiplication of point P by integer k."""
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_addition(result, addend, A, Pmod)
        addend = point_addition(addend, addend, A, Pmod)
        k >>= 1
    
    return result

def generate_keys(A, P, Gx, Gy, N):
    """Generates a private key and corresponding public key."""
    private_key = random.randint(1, N - 1)
    public_key = scalar_multiplication(private_key, (Gx, Gy), A, P)
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key, A, P):
    """Computes the shared secret using private key and peer's public key."""
    shared_secret = scalar_multiplication(private_key, peer_public_key, A, P)
    return shared_secret

def aes_encrypt(shared_secret, plaintext):
    """Encrypts a message using AES with the shared secret."""
    key = hashlib.sha256(str(shared_secret[0]).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(shared_secret, ciphertext):
    """Decrypts an AES-encrypted message."""
    key = hashlib.sha256(str(shared_secret[0]).encode()).digest()
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]), AES.block_size).decode()

# Generate key pairs using secp256k1
alice_private1, alice_public1 = generate_keys(A1, P1, Gx1, Gy1, N1)
bob_private1, bob_public1 = generate_keys(A1, P1, Gx1, Gy1, N1)

# Generate key pairs using secp192r1
alice_private2, alice_public2 = generate_keys(A2, P2, Gx2, Gy2, N2)
bob_private2, bob_public2 = generate_keys(A2, P2, Gx2, Gy2, N2)

# Derive shared secrets
alice_shared_secret1 = derive_shared_secret(alice_private1, bob_public1, A1, P1)
bob_shared_secret1 = derive_shared_secret(bob_private1, alice_public1, A1, P1)

alice_shared_secret2 = derive_shared_secret(alice_private2, bob_public2, A2, P2)
bob_shared_secret2 = derive_shared_secret(bob_private2, alice_public2, A2, P2)

# Encrypt and decrypt message
message = "Hell0 SRM AP"
ciphertext1 = aes_encrypt(alice_shared_secret1, message)
decrypted_message1 = aes_decrypt(bob_shared_secret1, ciphertext1)

ciphertext2 = aes_encrypt(alice_shared_secret2, message)
decrypted_message2 = aes_decrypt(bob_shared_secret2, ciphertext2)

print("Curve secp256k1: Decrypted message:", decrypted_message1)
print("Curve secp192r1: Decrypted message:", decrypted_message2)
