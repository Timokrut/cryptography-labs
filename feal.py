from typing import Tuple
import sys
import argparse

BLOCK_SIZE = 8  # FEAL блок 64 бита = 8 байт

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
    """
    Малые преобразования, использующиеся в FEAL.
    Это элементарная 8-бит функция, используемая в вариантах FEAL.
    Возвращает пару байт.
    """
    x = (a + b) & 0xFF
    y = rol8(a ^ b, 2)
    return x, y

def feal_round_function(x_bytes: bytes, k_bytes: bytes) -> bytes:
    """
    Функция F для раунда:
    - x_bytes: 4 байта (левый/правый 32-бита разбитые по байтам)
    - k_bytes: 4 байта раундового ключа
    Возвращает 4 байта, результат F.
    """

    # Разбиваем на байты
    x = list(x_bytes)
    k = list(k_bytes)

    # Пример последовательности операций (упрощённая, но рабочая)
    # Это учебная конструкция, повторяющая логику FEAL-4.
    a0 = x[0] ^ k[0]
    a1 = x[1] ^ k[1]
    a2 = x[2] ^ k[2]
    a3 = x[3] ^ k[3]

    # парные преобразования
    t0, t1 = f_box(a0, a1)
    t2, t3 = f_box(a2, a3)

    # смешивание
    r0 = t0 ^ t2
    r1 = t1 ^ t3
    r2 = (t2 + t0) & 0xFF
    r3 = (t3 + t1) & 0xFF

    return bytes([r0, r1, r2, r3])

def key_schedule(key: bytes, rounds: int = 4) -> list:
    """
    Простая генерация раундовых ключей из 8-байтного ключа.
    Возвращает список раундовых ключей (по 4 байта каждый).
    В FEAL на практике ключевое расписание сложнее; здесь учебная версия.
    """
    if len(key) != 8:
        raise ValueError("Ключ должен быть 8 байт (64 бита) для этой реализации.")
    k = list(key)
    subkeys = []
    # Простая генерация — комбинируем байты и слегка трансформируем
    
    for i in range(rounds + 1):  # +1 иногда нужен для финального шага
        # генерируем 4-байтный ключ для раунда i
        s0 = (k[0] + i + k[4]) & 0xFF
        s1 = (k[1] ^ (i*3) ^ k[5]) & 0xFF
        s2 = (k[2] + (i*5) + k[6]) & 0xFF
        s3 = (k[3] ^ (i*7) ^ k[7]) & 0xFF
        subkeys.append(bytes([s0, s1, s2, s3]))
        
        # немного трансформируем ключ для следующей итерации
        k = [rol8(x ^ i, (i % 7) + 1) for x in k]
    return subkeys

def feal_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Зашифровать 8-байтный блок (FEAL-4 учебная версия)."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть 8 байт.")
    subkeys = key_schedule(key, rounds=4)
    
    # Разбиваем 64 бита на 2 слова по 4 байта
    L = block[:4]
    R = block[4:]
    
    # 4 раунда (FEAL-4)
    for r in range(4):
        Fout = feal_round_function(R, subkeys[r])
        # L' = R
        L, R = R, bytes(x ^ y for x, y in zip(L, Fout))
    
    # финальная перестановка
    cipher = R + L
    return cipher

def feal_decrypt_block(block: bytes, key: bytes) -> bytes:
    """Дешифровать 8-байтный блок (обратная операция к feal_encrypt_block)."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть 8 байт.")
    subkeys = key_schedule(key, rounds=4)
    
    # обратим финальную перестановку
    R = block[:4]
    L = block[4:]
    
    # обратные раунды
    for r in reversed(range(4)):
        Fout = feal_round_function(L, subkeys[r])
        newR = bytes(x ^ y for x, y in zip(R, Fout))
        R, L = L, newR
    plain = L + R
    return plain

# ---------------------------
#        Режим ECB 
# ---------------------------
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

# ---------------------------
#       Работа с BMP24
# ---------------------------
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

# ---------------------------
# Работа с произвольным файлом (шифровать все байты)
# ---------------------------
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

# ---------------------------
# CLI 
# ---------------------------
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
