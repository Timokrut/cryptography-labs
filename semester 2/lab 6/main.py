import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b

    return a

def text_to_bits(text):
    bits = []
    for c in text:
        b = format(ord(c), '08b')
        bits.extend([int(x) for x in b])
    return bits

def bits_to_text(bits):
    text = ''

    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        byte_str = ''.join(str(x) for x in byte)
        text += chr(int(byte_str, 2))
    return text

def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]

def generate_keys():
    # Два простых числа
    # p ≡ q ≡ 3 (mod 4)
    p = 499
    q = 547

    n = p * q
    return n, (p, q)

def encrypt(message, n):
    m_bits = text_to_bits(message)
    t = len(m_bits)

    # выбираем случайныый x0
    while True:
        x0 = random.randint(2, n - 1)
        if gcd(x0, n) == 1: # -> взаимно простое
            break

    x = x0
    gamma = []

    # генерация потока с помощью генератора Блюма-Блюма-Шуба (BBS)
    for _ in range(t):
        x = pow(x, 2, n)
        # младший бит
        gamma.append(x % 2)

    cipher_bits = xor_bits(m_bits, gamma)

    return cipher_bits, x

def decrypt(cipher_bits, xt, private_key):
    p, q = private_key
    n = p * q
    t = len(cipher_bits)

    # степени
    ap = pow((p + 1) // 4, t, p - 1)
    aq = pow((q + 1) // 4, t, q - 1)

    # восстанавливаем остатки x0 по модулю p / q
    rp = pow(xt, ap, p)
    rq = pow(xt, aq, q)

    # КТО
    yp = pow(q, -1, p)
    yq = pow(p, -1, q)

    # восстанавливаем x0
    x0 = (rp * q * yp + rq * p * yq) % n

    # заново генирируем поток
    x = x0
    gamma = []

    for _ in range(t):
        x = pow(x, 2, n)
        gamma.append(x % 2)

    message_bits = xor_bits(cipher_bits, gamma)

    return bits_to_text(message_bits)

if __name__ == "__main__":
    public_key, private_key = generate_keys()
    print("PK:", public_key)
    print("SK:", private_key)

    message = "HELLO"
    print("Исходное сообщение:", message)

    cipher_bits, xt = encrypt(message, public_key)
    print("Шифртекст:", ''.join(str(x) for x in cipher_bits))
    print("xt =", xt)

    decrypted = decrypt(cipher_bits, xt, private_key)
    print("Расшифрованное сообщение:", decrypted)