import random
from m_sha1 import sha1


def is_prime(n, k=5):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n

def generate_params():
    q = generate_prime(160)

    while True:
        b = random.getrandbits(864)
        p = b * q + 1
        if is_prime(p):
            break

    while True:
        g = random.randint(2, p - 2)
        a = pow(g, (p - 1) // q, p)
        if a > 1:
            break

    return p, q, a

def generate_keys(p, q, a):
    x = random.randint(1, q - 1)
    y = pow(a, x, p)
    return x, y

def hash_msg(msg):
    return int(sha1(msg), 16)

def sign(msg, p, q, a, x):
    h = hash_msg(msg) % q
    if h == 0:
        h = 1

    while True:
        k = random.randint(1, q - 1)
        r = pow(a, k, p) % q
        if r == 0:
            continue

        s = (k * h + x * r) % q
        if s == 0:
            continue

        return r, s

def verify(msg, r, s, p, q, a, y):
    if not (0 < r < q and 0 < s < q):
        return False

    h = hash_msg(msg) % q
    if h == 0:
        h = 1

    v = pow(h, -1, q)
    z1 = (s * v) % q
    z2 = (-r * v) % q

    u = (pow(a, z1, p) * pow(y, z2, p) % p) % q
    return u == r


if __name__ == "__main__":
    # q - большое простое число (~160 bit)
    # p = b * q + 1
    # a = g^((p-1)/q) mod p
    p, q, a = generate_params()
    print(f"q = {q}")
    print(f"p = {p}")
    print(f"a = {a}")

    # x - случайное число от 1 до q
    # y = a ^ x mod p
    x, y = generate_keys(p, q, a)
    print(f"Private Key: {x}")
    print(f"Public Key: {y}")

    msg = "test message"
    
    # подпись
    r, s = sign(msg, p, q, a, x)
    print(f"r: {r}")
    print(f"s: {s}")

    print("Valid:", verify(msg, r, s, p, q, a, y))