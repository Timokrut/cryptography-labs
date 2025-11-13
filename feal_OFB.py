from typing import Tuple
from PIL import Image 
import random
import os

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

def ofb_keystream_generator(key: bytes, iv: bytes):
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть размера блока (8 байт).")
    prev = iv
    while True:
        out = feal_encrypt_block(prev, key)
        yield out
        prev = out

def ofb_encrypt_stream(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    ks_gen = ofb_keystream_generator(key, iv)
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        ks = next(ks_gen)
        ks_truncated = ks[:len(block)]
        out.extend(x ^ y for x, y in zip(block, ks_truncated))
    return bytes(out)

def ofb_decrypt_stream(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return ofb_encrypt_stream(ciphertext, key, iv)

BMP_HEADER_SIZE = 54

def encrypt_bmp24_ecb(in_path: str, out_path: str, key: bytes):
    with open(in_path, "rb") as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]
    encrypted_body = ecb_encrypt_stream(body, key)
    with open(out_path, "wb") as f:
        f.write(header + encrypted_body)
    print(f"Зашифровано BMP24 (ECB) -> {out_path}")

def decrypt_bmp24_ecb(in_path: str, out_path: str, key: bytes):
    with open(in_path, "rb") as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]
    decrypted_body = ecb_decrypt_stream(body, key)
    with open(out_path, "wb") as f:
        f.write(header + decrypted_body)
    print(f"Дешифровано BMP24 (ECB) -> {out_path}")

def encrypt_bmp24_ofb(in_path: str, out_path: str, key: bytes, iv: bytes):
    with open(in_path, "rb") as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]
    encrypted_body = ofb_encrypt_stream(body, key, iv)
    with open(out_path, "wb") as f:
        f.write(header + encrypted_body)
    print(f"Зашифровано BMP24 (OFB) -> {out_path}")

def decrypt_bmp24_ofb(in_path: str, out_path: str, key: bytes, iv: bytes):
    # decrypt == encrypt
    with open(in_path, "rb") as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]
    decrypted_body = ofb_decrypt_stream(body, key, iv)
    with open(out_path, "wb") as f:
        f.write(header + decrypted_body)
    print(f"Дешифровано BMP24 (OFB) -> {out_path}")

# ------------------ Эксперимент: изменить 1 пиксель в зашифрованном BMP и посчитать эффект ------------------
def flip_pixel_in_cipher_bmp(cipher_path: str, out_path: str, pixel_index: int, image_width: int):
    with open(cipher_path, "rb") as f:
        all_data = bytearray(f.read())
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")
    header = all_data[:BMP_HEADER_SIZE]
    body = all_data[BMP_HEADER_SIZE:]

    img = Image.open(cipher_path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    w, h = img.size
    if pixel_index < 0 or pixel_index >= w * h:
        raise ValueError("pixel_index вне диапазона.")
    x = pixel_index % w
    y = pixel_index // w
    pixels = img.load()
    r,g,b = pixels[x,y]

    pixels[x,y] = ((r ^ 0xFF) & 0xFF, g, b)
    img.save(out_path)
    print(f"Изменён пиксель {pixel_index} в {out_path}")

def flip_line_in_cipher_bmp(cipher_path: str, out_path: str, line_index: int, image_width: int, image_height: int):
    with open(cipher_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < BMP_HEADER_SIZE:
        raise ValueError("Файл слишком мал, чтобы быть BMP.")

    header = data[:BMP_HEADER_SIZE]
    body = data[BMP_HEADER_SIZE:]

    row_bytes = ((image_width * 3 + 3) // 4) * 4
    if line_index < 0 or line_index >= image_height:
        raise ValueError("line_index вне диапазона.")

    real_y = (image_height - 1) - line_index
    offset = real_y * row_bytes

    if offset + row_bytes > len(body):
        raise ValueError("Строка выходит за пределы тела BMP.")

    for i in range(offset, offset + row_bytes):
        body[i] ^= 0xFF

    with open(out_path, "wb") as f:
        f.write(header + body)

    print(f"Изменена линия {line_index} в {out_path}")

def count_different_pixels(img_path1: str, img_path2: str) -> int:
    a = Image.open(img_path1).convert("RGB")
    b = Image.open(img_path2).convert("RGB")
    if a.size != b.size:
        raise ValueError("Размеры изображений не совпадают.")
    w,h = a.size
    pa = a.load()
    pb = b.load()
    cnt = 0
    for y in range(h):
        for x in range(w):
            if pa[x,y] != pb[x,y]:
                cnt += 1
    return cnt

def experiment_error_propagation(original_bmp: str, key: bytes, iv: bytes, pixel_to_flip: int, image_width: int):
    base, ext = os.path.splitext(original_bmp)
    ecb_cipher = base + "_ecb_cipher.bmp"
    ofb_cipher = base + "_ofb_cipher.bmp"
    ecb_corrupted = base + "_ecb_corrupted.bmp"
    ofb_corrupted = base + "_ofb_corrupted.bmp"
    ecb_decrypted = base + "_ecb_decrypted_after_corrupt.bmp"
    ofb_decrypted = base + "_ofb_decrypted_after_corrupt.bmp"
    ecb_decrypted_clean = base + "_ecb_decrypted_clean.bmp"
    ofb_decrypted_clean = base + "_ofb_decrypted_clean.bmp"

    encrypt_bmp24_ecb(original_bmp, ecb_cipher, key)
    encrypt_bmp24_ofb(original_bmp, ofb_cipher, key, iv)

    image = Image.open(original_bmp)
    width, height = image.size
    line_to_flip = height // 2

    flip_line_in_cipher_bmp(ecb_cipher, ecb_corrupted, line_to_flip, width, height)
    flip_line_in_cipher_bmp(ofb_cipher, ofb_corrupted, line_to_flip, width, height)
 

    # flip_pixel_in_cipher_bmp(ecb_cipher, ecb_corrupted, pixel_to_flip, image_width)
    # flip_pixel_in_cipher_bmp(ofb_cipher, ofb_corrupted, pixel_to_flip, image_width)

    try:
        decrypt_bmp24_ecb(ecb_corrupted, ecb_decrypted, key)
    except ValueError as e:
        print("Предупреждение: ошибка паддинга при дешифровке ECB (ожидаемо). Попробуем сохранить без паддинга.")
        with open(ecb_corrupted, "rb") as f:
            all_data = f.read()
        header = all_data[:BMP_HEADER_SIZE]
        body = all_data[BMP_HEADER_SIZE:]

        out = bytearray()
        for i in range(0, len(body), BLOCK_SIZE):
            block = body[i:i+BLOCK_SIZE]
            if len(block) < BLOCK_SIZE:
                break
            out.extend(feal_decrypt_block(block, key))
        with open(ecb_decrypted, "wb") as f:
            f.write(header + bytes(out))
    decrypt_bmp24_ofb(ofb_corrupted, ofb_decrypted, key, iv)

    try:
        decrypt_bmp24_ecb(ecb_cipher, ecb_decrypted_clean, key)
    except ValueError as e:
        print("Предупреждение: ошибка паддинга при дешифровке ECB (ожидаемо). Попробуем сохранить без паддинга.")

        with open(ecb_cipher, "rb") as f:
            all_data = f.read()
        header = all_data[:BMP_HEADER_SIZE]
        body = all_data[BMP_HEADER_SIZE:]

        out = bytearray()
        for i in range(0, len(body), BLOCK_SIZE):
            block = body[i:i+BLOCK_SIZE]
            if len(block) < BLOCK_SIZE:
                break
            out.extend(feal_decrypt_block(block, key))
        with open(ecb_decrypted_clean, "wb") as f:
            f.write(header + bytes(out))
    decrypt_bmp24_ofb(ofb_cipher, ofb_decrypted_clean, key, iv)

    diff_ecb = count_different_pixels(original_bmp, ecb_decrypted)
    diff_ofb = count_different_pixels(original_bmp, ofb_decrypted)

    print("Результаты эксперимента:")
    print(f"ECB: число отличающихся пикселей после изменения 1 пикселя в шифртексте = {diff_ecb}")
    print(f"OFB: число отличающихся пикселей после изменения 1 пикселя в шифртексте = {diff_ofb}")

    return {
        "ecb_cipher": ecb_cipher,
        "ofb_cipher": ofb_cipher,
        "ecb_corrupted": ecb_corrupted,
        "ofb_corrupted": ofb_corrupted,
        "ecb_decrypted": ecb_decrypted,
        "ofb_decrypted": ofb_decrypted,
        "diff_ecb": diff_ecb,
        "diff_ofb": diff_ofb,
    }

def parse_hex_key(s: str) -> bytes:
    s = s.strip()
    if len(s) != 16:
        raise ValueError("Ожидается 16 hex-символов (8 байт).")
    return bytes.fromhex(s)

def random_iv() -> bytes:
    return bytes(random.getrandbits(8) for _ in range(BLOCK_SIZE))

if __name__ == "__main__":
    key = parse_hex_key("0011223344556677")
    iv = random_iv()
    width = Image.open("image2.bmp").size[0]

    res = experiment_error_propagation("image2.bmp", key, iv, pixel_to_flip=300, image_width=width)
    print(res)


