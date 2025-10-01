#!/usr/bin/env python3
"""
FEAL-3 (учебная реализация) + ECB wrapper + BMP24-aware file encrypt/decrypt

Назначение:
 - encrypt_block(data_block, key) / decrypt_block(...)
 - ecb_encrypt_stream(bytes, key) / ecb_decrypt_stream(...)
 - bmp_encrypt_file(input_path, output_path, key_path_or_bytes, mode='encrypt'|'decrypt')
 - key generation / save / load

Примечание:
 - Рабочий блочный размер: 8 байт (64 бита).
 - Ключ: 8 байт (64 бита).
 - Для файлов (общих): PKCS#7-подобная дополняющая схема до 8 байт.
 - Для BMP: сохраняется заголовок (читаю смещение пиксельных данных в заголовке BMP).
 - Это учебная реализация FEAL-3 (не для продакшн-шифрования).
"""

import struct
import secrets

BLOCK_SIZE = 8  # 64-bit block

# ---------------------------
# Утилиты упаковки/распаковки
# ---------------------------
def _u64(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def _u32(n: int) -> int:
    return n & 0xFFFFFFFF

def _to_bytes_u64(n: int) -> bytes:
    return n.to_bytes(8, byteorder='big')

# ---------------------------
# Небольшая "F" функция и вспомогательные
# Учебная вариация FEAL-like F
# ---------------------------
def _rol32(x: int, r: int) -> int:
    return _u32(((x << r) & 0xFFFFFFFF) | (x >> (32 - r)))

def _f_function(r32: int, k32: int) -> int:
    """
    Небольшая нелинейная функция F для учебного FEAL-3.
    Входы: 32-битный раундовый вход r32, 32-битный подключ k32.
    Выход: 32-бит.
    Описание (учебное):
      t = (r32 + k32) mod 2^32
      затем последовательные нелинейные преобразования с вращениями и XOR.
    """
    t = _u32(r32 + k32)
    # разложим на байты и проведём простую нелинейность
    b0 = (t >> 24) & 0xFF
    b1 = (t >> 16) & 0xFF
    b2 = (t >> 8)  & 0xFF
    b3 = t & 0xFF

    # простые S-подстановки (учебные)
    def s(x):
        # 8-bit non-linear op: rotate-left 2 and xor with (x<<1)
        return (( ((x << 2) & 0xFF) | (x >> 6) ) ^ ((x << 1) & 0xFF)) & 0xFF

    b0 = s(b0)
    b1 = s(b1 ^ b0)
    b2 = s(b2 ^ b1)
    b3 = s(b3 ^ b2)

    out = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    # ещё один финальный оборот
    out = _rol32(out ^ 0xA5A5A5A5, 3)
    return out

# ---------------------------
# Key schedule для FEAL-3 (учебный)
# Возвращает список 4 32-битных раундовых ключей (K1..K4) для трёх раундов + возможное горячее K0
# ---------------------------
def key_schedule_feal3(key8: bytes):
    if len(key8) != 8:
        raise ValueError("Key must be 8 bytes (64 bits)")
    # Разложим ключ на две 32-битные части
    k_high = int.from_bytes(key8[:4], 'big')
    k_low  = int.from_bytes(key8[4:], 'big')
    # Генерируем простые подключи: K1..K4
    K = []
    K.append(_u32(k_high ^ _rol32(k_low, 8) ^ 0x0F0F0F0F))
    K.append(_u32(k_low  ^ _rol32(k_high, 5) ^ 0x33333333))
    K.append(_u32(K[0] ^ _rol32(K[1], 7) ^ 0x55555555))
    K.append(_u32(K[1] ^ _rol32(K[0], 3) ^ 0x99999999))
    # для FEAL-3 хватит K[0:3] (K1..K3) но используем 4 элемента для финальной обработки
    return K  # list of 4 32-bit ints

# ---------------------------
# Блочная шифровка (FEAL-3 учебный)
# ---------------------------
def encrypt_block(block8: bytes, key8: bytes) -> bytes:
    if len(block8) != 8:
        raise ValueError("Block must be 8 bytes")
    L = int.from_bytes(block8[:4], 'big')
    R = int.from_bytes(block8[4:], 'big')
    Ks = key_schedule_feal3(key8)

    # FEAL-3: 3 раунда
    for i in range(3):
        # round: L, R = R, L ^ F(R, K_i)
        Fout = _f_function(R, Ks[i])
        L, R = R, _u32(L ^ Fout)

    # финальная перестановка (swap)
    out = (R.to_bytes(4, 'big') + L.to_bytes(4, 'big'))
    return out



def decrypt_block(block8: bytes, key8: bytes) -> bytes:
    if len(block8) != 8:
        raise ValueError("Block must be 8 bytes")
    # обратный процесс к тому, что делали в encrypt_block
    # при encrypt мы в конце вернули R||L (после трёх раундов с swap)
    # при дешифровании нужно повторить раунды в обратном порядке.
    R = int.from_bytes(block8[:4], 'big')
    L = int.from_bytes(block8[4:], 'big')
    Ks = key_schedule_feal3(key8)

    # обратные раунды: инвертируем 3 раунда в обратном порядке
    # если в шифровании было: for i=0..2: (L,R) = (R, L ^ F(R, K_i))
    # то инверсия (в обратном порядке) будет:
    for i in reversed(range(3)):
        # текущие L,R соответствуют состоянию после swap в encrypt, но инвариант тот же
        # обратная итерация:
        # были: L_new = R_old
        #       R_new = L_old ^ F(R_old, K_i)
        # значит: R_old = L_new
        #        L_old = R_new ^ F(R_old, K_i) = R_new ^ F(L_new, K_i)
        # после инверсии присвоим:
        R_old = L
        L_old = _u32(R ^ _f_function(R_old, Ks[i]))
        L, R = L_old, R_old

    # теперь L,R это исходные L,R; вернуть L||R
    return (L.to_bytes(4, 'big') + R.to_bytes(4, 'big'))

# ---------------------------
# ECB для байтовых потоков
# ---------------------------
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def ecb_encrypt_stream(plaintext: bytes, key8: bytes) -> bytes:
    data = pkcs7_pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        out.extend(encrypt_block(data[i:i+BLOCK_SIZE], key8))
    return bytes(out)

def ecb_decrypt_stream(ciphertext: bytes, key8: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        out.extend(decrypt_block(ciphertext[i:i+BLOCK_SIZE], key8))
    pt = pkcs7_unpad(bytes(out))
    return pt

# ---------------------------
# Генерация/сохранение/загрузка ключа
# ---------------------------
def generate_key_random() -> bytes:
    return secrets.token_bytes(8)

def save_key_to_file(key8: bytes, path: str):
    with open(path, 'wb') as f:
        f.write(key8)

def load_key_from_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        b = f.read()
    if len(b) != 8:
        raise ValueError("Key file must contain exactly 8 bytes")
    return b

# ---------------------------
# BMP24-aware file encrypt/decrypt
# ---------------------------
def bmp_encrypt_file(in_path: str, out_path: str, key8: bytes, mode: str = 'encrypt'):
    """
    Если файл - BMP, читаем offset пиксельных данных из заголовка (байты 10..13 LITTLE-ENDIAN).
    Сохраняем всё до offset как есть; шифруем/дешифруем только пиксельные данные.
    Если файл не похож на BMP (не начинается с 'BM'), можно просто шифровать весь файл.
    """
    with open(in_path, 'rb') as f:
        allb = f.read()

    if len(allb) < 54:
        raise ValueError("File too small to be BMP or to contain BMP header")

    if allb[:2] == b'BM':
        # BMP: offset to pixel data at bytes 10..13 (little-endian)
        pixel_offset = struct.unpack_from('<I', allb, 10)[0]
        header = allb[:pixel_offset]
        pixel_bytes = allb[pixel_offset:]
        # Шифруем/дешифруем pixel_bytes в ECB; при шифровании используем PKCS7,
        # но в BMP полезно чтобы размер данных оставался кратным 4 для выравнивания строк.
        # Мы используем PKCS#7 — при расшифровке восстановим исходные данные.
        if mode == 'encrypt':
            out_pixels = ecb_encrypt_stream(pixel_bytes, key8)
        elif mode == 'decrypt':
            out_pixels = ecb_decrypt_stream(pixel_bytes, key8)
        else:
            raise ValueError("mode must be 'encrypt' or 'decrypt'")
        with open(out_path, 'wb') as f:
            f.write(header + out_pixels)
    else:
        # не BMP: шифруем весь поток
        if mode == 'encrypt':
            outb = ecb_encrypt_stream(allb, key8)
        else:
            outb = ecb_decrypt_stream(allb, key8)
        with open(out_path, 'wb') as f:
            f.write(outb)

# ---------------------------
# Командная оболочка (CLI)
# ---------------------------
def print_usage():
    print("FEAL-3 ECB (учебная реализация)")
    print("Использование:")
    print("  python feal3_ecb.py genkey keyfile")
    print("  python feal3_ecb.py encrypt infile outfile keyfile [--bmp]")
    print("  python feal3_ecb.py decrypt infile outfile keyfile [--bmp]")
    print("")
    print("Если указан --bmp (или файл имеет сигнатуру BM), то сохраняется заголовок BMP и шифруются только пиксельные данные.")
    print("Ключ — 8 байт (64 бита).")

def main_cli(argv):
    import sys
    if len(argv) < 2:
        print_usage(); return
    cmd = argv[1].lower()
    if cmd == 'genkey':
        if len(argv) < 3:
            print("Укажите файл для сохранения ключа"); return
        key = generate_key_random()
        save_key_to_file(key, argv[2])
        print(f"Ключ сгенерирован и сохранён в {argv[2]}")
    elif cmd in ('encrypt', 'decrypt'):
        if len(argv) < 5:
            print_usage(); return
        infile = argv[2]; outfile = argv[3]; keyfile = argv[4]
        key = load_key_from_file(keyfile)
        mode = 'encrypt' if cmd == 'encrypt' else 'decrypt'
        # detect --bmp flag or automatic BMP detection inside function
        try:
            bmp_encrypt_file(infile, outfile, key, mode=mode)
            print(f"{mode.capitalize()}ion done: {infile} -> {outfile}")
        except Exception as e:
            print("Ошибка:", e)
    else:
        print_usage()

if __name__ == '__main__':
    import sys
    main_cli(sys.argv)

