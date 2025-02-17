def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modInverse(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    return -1

def generateKeys():
    p = 3
    q = 5
    
    n = p * q
    phi = (p - 1) * (q - 1)


    for e in range(2, phi):
        if gcd(e, phi) == 1:
            break

    d = modInverse(e, phi)

    return e,d,n

if __name__ == "__main__":
    e,d,n=generateKeys()
    print(f"Keys generated:\ne: {e}\nd: {d}\nn: {n}")