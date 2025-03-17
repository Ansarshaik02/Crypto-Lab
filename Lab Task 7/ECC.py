import random

# secp256k1 Curve Parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Prime field
A = 0  # Curve parameter a
B = 7  # Curve parameter b
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Order of the curve

def inverse_mod(k, p):
    """Computes the modular inverse of k modulo p."""
    return pow(k, -1, p)

def point_addition(P1, P2):
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

def scalar_multiplication(k, P):
    """Performs scalar multiplication of point P by integer k."""
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_addition(result, addend)
        addend = point_addition(addend, addend)
        k >>= 1
    
    return result

def generate_keys():
    """Generates a private key and corresponding public key."""
    private_key = random.randint(1, N - 1)
    public_key = scalar_multiplication(private_key, (Gx, Gy))
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    """Computes the shared secret using private key and peer's public key."""
    shared_secret = scalar_multiplication(private_key, peer_public_key)
    return shared_secret

# Generate key pairs for Alice and Bob
alice_private, alice_public = generate_keys()
bob_private, bob_public = generate_keys()

# Exchange public keys and derive shared secret
alice_shared_secret = derive_shared_secret(alice_private, bob_public)
bob_shared_secret = derive_shared_secret(bob_private, alice_public)

# Verify that both computed the same shared secret
assert alice_shared_secret == bob_shared_secret
print("Key exchange successful! Shared secret derived correctly.")
