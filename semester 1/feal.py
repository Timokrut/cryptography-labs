from typing import Tuple

BLOCK_SIZE = 8

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Некорректный паддинг (длина не кратна размеру блока).")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Неверный PKCS#7 паддинг.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Неверный PKCS#7 паддинг.")
    return data[:-pad_len]

def rol8(x: int, n: int) -> int:
    return ((x << n) & 0xFF) | ((x & 0xFF) >> (8 - n))

def f_box(a: int, b: int) -> Tuple[int,int]:
    x = (a + b) & 0xFF
    y = rol8(a ^ b, 2)
    return x, y

def feal_round_function(x_bytes: bytes, k_bytes: bytes) -> bytes:
    x = list(x_bytes)
    k = list(k_bytes)

    a0 = x[0] ^ k[0]
    a1 = x[1] ^ k[1]
    a2 = x[2] ^ k[2]
    a3 = x[3] ^ k[3]

    t0, t1 = f_box(a0, a1)
    t2, t3 = f_box(a2, a3)

    r0 = t0 ^ t2
    r1 = t1 ^ t3
    r2 = (t2 + t0) & 0xFF
    r3 = (t3 + t1) & 0xFF

    return bytes([r0, r1, r2, r3])

def key_schedule(key: bytes, rounds: int = 4) -> list:
    if len(key) != 8:
        raise ValueError("Ключ должен быть 8 байт (64 бита) для этой реализации.")
    k = list(key)
    subkeys = []
    
    for i in range(rounds + 1): 
        s0 = (k[0] + i + k[4]) & 0xFF
        s1 = (k[1] ^ (i*3) ^ k[5]) & 0xFF
        s2 = (k[2] + (i*5) + k[6]) & 0xFF
        s3 = (k[3] ^ (i*7) ^ k[7]) & 0xFF
        subkeys.append(bytes([s0, s1, s2, s3]))
        
        k = [rol8(x ^ i, (i % 7) + 1) for x in k]
    return subkeys

def feal_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть 8 байт.")
    subkeys = key_schedule(key, rounds=4)
    
    L = block[:4]
    R = block[4:]
    
    for r in range(4):
        Fout = feal_round_function(R, subkeys[r])
        L, R = R, bytes(x ^ y for x, y in zip(L, Fout))
    
    cipher = R + L
    return cipher

def feal_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть 8 байт.")
    subkeys = key_schedule(key, rounds=4)
    
    R = block[:4]
    L = block[4:]
    
    for r in reversed(range(4)):
        Fout = feal_round_function(L, subkeys[r])
        newR = bytes(x ^ y for x, y in zip(R, Fout))
        R, L = L, newR
    plain = L + R
    return plain

def ecb_encrypt_stream(plaintext: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        out.extend(feal_encrypt_block(block, key))
    return bytes(out)

def ecb_decrypt_stream(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифртекста не кратна размеру блока.")
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        out.extend(feal_decrypt_block(block, key))
    return pkcs7_unpad(bytes(out), BLOCK_SIZE)

BMP_HEADER_SIZE = 54

def encrypt_bmp24_file(in_path: str, out_path: str, key: bytes):
    with open(in_path, "rb") as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]
    encrypted_body = ecb_encrypt_stream(body, key)
    with open(out_path, "wb") as f:
        f.write(header + encrypted_body)
    print(f"Зашифровано BMP24 -> {out_path}")

def decrypt_bmp24_file(in_path: str, out_path: str, key: bytes):
    with open(in_path, "rb") as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]
    decrypted_body = ecb_decrypt_stream(body, key)
    with open(out_path, "wb") as f:
        f.write(header + decrypted_body)
    print(f"Дешифровано BMP24 -> {out_path}")

def encrypt_file_any(in_path: str, out_path: str, key: bytes):
    with open(in_path, "rb") as f:
        data = f.read()
    enc = ecb_encrypt_stream(data, key)
    with open(out_path, "wb") as f:
        f.write(enc)
    print(f"Зашифровано -> {out_path}")

def decrypt_file_any(in_path: str, out_path: str, key: bytes):
    with open(in_path, "rb") as f:
        data = f.read()
    dec = ecb_decrypt_stream(data, key)
    with open(out_path, "wb") as f:
        f.write(dec)
    print(f"Дешифровано -> {out_path}")

def parse_hex_key(s: str) -> bytes:
    s = s.strip()
    if len(s) != 16:
        raise ValueError("Ожидается 16 hex-символов (8 байт).")
    return bytes.fromhex(s)

def interactive_menu():
    while True:
        print("\nВыберите режим:")
        print("1 - Зашифровать файл")
        print("2 - Дешифровать файл")
        print("3 - Выход")
        choice = input(">> ").strip()
        if choice == "3":
            print("Выход.")
            break
        if choice not in ("1", "2"):
            print("Неверный выбор.")
            continue
        in_path = input("Путь к входному файлу: ").strip()
        out_path = input("Путь к выходному файлу: ").strip()
        bmp_mode = input("Файл BMP24? (y/n): ").strip().lower().startswith("y")
        key_hex = input("Ключ (16 hex символов, 8 байт): ").strip()
        try:
            key = parse_hex_key(key_hex)
        except Exception as e:
            print("Ошибка ключа:", e)
            continue
        try:
            if choice == "1":
                if bmp_mode:
                    encrypt_bmp24_file(in_path, out_path, key)
                else:
                    encrypt_file_any(in_path, out_path, key)
            else:
                if bmp_mode:
                    decrypt_bmp24_file(in_path, out_path, key)
                else:
                    decrypt_file_any(in_path, out_path, key)
        except Exception as e:
            print("Ошибка при обработке файла:", e)

if __name__ == "__main__":
    interactive_menu()
