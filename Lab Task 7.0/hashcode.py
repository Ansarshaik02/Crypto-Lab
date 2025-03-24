import hashlib

def generate_sha512_hash(text):
    hash_object = hashlib.sha512(text.encode()) 
    return hash_object.hexdigest()             

text = input("Enter text: ")
hash_code = generate_sha512_hash(text)

print("SHA-512 Hash:", hash_code)
