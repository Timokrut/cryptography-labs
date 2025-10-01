import random 
import math 

M = 128 

def generate_key():
    while True:
        a = random.randint(1, M - 1)
        if math.gcd(a, M) == 1:
            break 

    b = random.randint(0, M - 1)
    return (a, b)

def encrypt(text: str, key: tuple[int, int]) -> str:
    a, b = key 
    result = []

    for char in text:
        x = ord(char) 
        y = (a * x + b) % M 
        result.append(chr(y))

    return ''.join(result)

def mod_inverse(a: int, m: int) -> int: 
    # расширенный алгоритм евлкида
    a = a % m 
    for x in range(1, m):
        if (a * x) % m == 1:
            return x 

    raise ValueError("Inversed element doesnt exist")

def decrypt(cipher: str, key: tuple[int, int]) -> str:
    a, b = key 
    a_inv = mod_inverse(a, M)
    result = []

    for char in cipher:
        y = ord(char)
        x = (a_inv * (y - b)) % M 
        result.append(chr(x))

    return ''.join(result)

if __name__ == "__main__":
    key = generate_key()
    print(f"Generated key: {key}")

    text = "Hello, Affine Cipher!"
    encrypted = encrypt(text, key)
    decrypted = decrypt(encrypted, key)

    print(f"Original: {text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
