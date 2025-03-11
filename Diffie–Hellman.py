import random


def power(base, exp, mod):
    result = 1
    base = base % mod
    while exp>0:
        if exp%2==1:
            result=(result * base) % mod
        base=(base*base)%mod
        exp =exp//2
    return result

def diffie_hellman():
    p = 23 
    g = 5 

    x = random.randint(1, 10)
    y = random.randint(1, 10)
    print(f"random x val: {x}")
    print(f"random y val: {y}")

    A = power(g, x, p)
    B = power(g, y, p)

    s_alice = power(B, x, p)
    s_bob = power(A, y, p)

    if s_alice == s_bob:
        print("Key exchange successful!")
        print(f"Shared secret: {s_alice}")
    else:
        print("Key exchange failed!")

diffie_hellman()