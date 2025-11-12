# -*- coding: utf-8 -*-
"""
FEAL implementation + статистические тесты над битовой последовательностью
(версия с анализом BMP-файлов и интерпретацией: пройден / не пройден)

Функции шифрования/дешифрования FEAL и режимы ECB/OFB оставлены из исходного кода.
Новые возможности:
 - analyze_block_stats(block, autocorr_d=1)  - тесты для произвольной битовой последовательности (блок/последовательность байтов)
 - analyze_bmp24(path, autocorr_d=1) - чтение BMP (без заголовка) и запуск тестов на всем теле
 - encrypt_bmp24_ecb/_ofb теперь по умолчанию выполняют анализ зашифрованного файла и печатают результат

Пример использования приведён внизу.
"""
from typing import Tuple, List, Dict
from PIL import Image  # pip install pillow
import random
import os
import math

BLOCK_SIZE = 8

# ----------------- исходный FEAL-код (как у вас) -----------------

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

# ------------------ ECB (ваше) ------------------
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

# ------------------ OFB (новое) ------------------
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

# ------------------ Файловые обёртки для BMP24 ------------------
BMP_HEADER_SIZE = 54

def encrypt_bmp24_ecb(in_path: str, out_path: str, key: bytes, analyze_after: bool = True):
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
    if analyze_after:
        print('
Авто-анализ зашифрованного файла:')
        analyze_bmp24(out_path)


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


def encrypt_bmp24_ofb(in_path: str, out_path: str, key: bytes, iv: bytes, analyze_after: bool = True):
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
    if analyze_after:
        print('
Авто-анализ зашифрованного файла:')
        analyze_bmp24(out_path)


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

# ------------------ НОВЫЕ СТАТИСТИЧЕСКИЕ ТЕСТЫ ------------------

def bytes_to_bitlist(data: bytes) -> List[int]:
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits


def freq_test(bits: List[int]) -> Dict[str, float]:
    n = len(bits)
    n1 = sum(bits)
    n0 = n - n1
    X1 = ((n0 - n1) ** 2) / n if n > 0 else float('nan')
    return {'n': n, 'n0': n0, 'n1': n1, 'X1': X1}


def serial_test(bits: List[int]) -> Dict[str, float]:
    n = len(bits)
    if n < 2:
        raise ValueError('Последовательность слишком коротка для двубитного теста.')
    n00 = n01 = n10 = n11 = 0
    for i in range(n - 1):
        a, b = bits[i], bits[i+1]
        if a == 0 and b == 0:
            n00 += 1
        elif a == 0 and b == 1:
            n01 += 1
        elif a == 1 and b == 0:
            n10 += 1
        else:
            n11 += 1
    n0 = bits.count(0)
    n1 = bits.count(1)
    X2 = (4.0 / (n - 1)) * (n00**2 + n01**2 + n10**2 + n11**2) - (2.0 / n) * (n0**2 + n1**2) + 1.0
    return {'n': n, 'n00': n00, 'n01': n01, 'n10': n10, 'n11': n11, 'n0': n0, 'n1': n1, 'X2': X2}


def choose_m_for_poker(n: int) -> int:
    # выбираем наибольшее m>=1 такое, что floor(n/m) >= 5 * 2^m
    m = 1
    while True:
        k = n // m
        if k < 5 * (2 ** m):
            return max(1, m-1)
        m += 1
        if m > 20:
            return max(1, m-1)


def poker_test(bits: List[int], m: int = None) -> Dict[str, float]:
    n = len(bits)
    if n < 1:
        raise ValueError('Пустая последовательность для покер-теста.')
    if m is None:
        m = choose_m_for_poker(n)
    if m < 1:
        m = 1
    k = n // m
    if k < 1:
        raise ValueError('Недостаточно бит для покер-теста с выбранным m.')
    # оставляем только k * m первых бит
    seq = bits[:k*m]
    counts = {}
    for i in range(k):
        chunk = seq[i*m:(i+1)*m]
        idx = 0
        for bit in chunk:
            idx = (idx << 1) | bit
        counts[idx] = counts.get(idx, 0) + 1
    # дополняем нулями для всех возможных паттернов
    for i in range(2**m):
        counts.setdefault(i, 0)
    sum_sq = sum(v*v for v in counts.values())
    X3 = ((2**m) / k) * sum_sq - k
    return {'n': n, 'm': m, 'k': k, 'counts': counts, 'X3': X3}


def runs_test(bits: List[int]) -> Dict[str, float]:
    n = len(bits)
    if n == 0:
        raise ValueError('Пустая последовательность для теста серий.')
    # собираем серии
    runs_zero = []  # длины разрывов (0)
    runs_one = []   # длины блоков (1)
    cur = bits[0]
    length = 1
    for b in bits[1:]:
        if b == cur:
            length += 1
        else:
            if cur == 0:
                runs_zero.append(length)
            else:
                runs_one.append(length)
            cur = b
            length = 1
    # добавить последнюю серию
    if cur == 0:
        runs_zero.append(length)
    else:
        runs_one.append(length)
    # ожидаемое число e_i
    e_i_list = {}
    i = 1
    while True:
        e_i = (n - i + 3) / (2 ** (i + 2))
        if e_i < 5:
            break
        e_i_list[i] = e_i
        i += 1
    k = max(e_i_list.keys()) if e_i_list else 0
    B = {i:0 for i in range(1, k+1)}
    G = {i:0 for i in range(1, k+1)}
    for r in runs_zero:
        if 1 <= r <= k:
            B[r] += 1
    for r in runs_one:
        if 1 <= r <= k:
            G[r] += 1
    X4 = 0.0
    for i in range(1, k+1):
        e = e_i_list[i]
        X4 += (B[i] - e)**2 / e
    for i in range(1, k+1):
        e = e_i_list[i]
        X4 += (G[i] - e)**2 / e
    return {'n': n, 'k': k, 'e_i': e_i_list, 'B': B, 'G': G, 'X4': X4}


def autocorrelation_test(bits: List[int], d: int) -> Dict[str, float]:
    n = len(bits)
    if d < 1 or d > n//2:
        raise ValueError('d должно быть 1 <= d <= floor(n/2)')
    A = 0
    for i in range(n - d):
        A += bits[i] ^ bits[i + d]
    X5 = 2.0 * (A - (n - d) / 2.0) / math.sqrt(n - d) if (n - d) > 0 else float('nan')
    return {'n': n, 'd': d, 'A': A, 'X5': X5}

# ------------------ Таблица хи-квадрат (часто используемые точки) ------------------
CHI2_CRIT = {
    1: {0.10: 2.70554, 0.05: 3.84146, 0.01: 6.63490, 0.001: 10.8276},
    2: {0.10: 4.6052,  0.05: 5.99146, 0.01: 9.21034, 0.001: 13.8155},
    3: {0.10: 6.25139, 0.05: 7.81473, 0.01: 11.3449, 0.001: 16.2662},
    4: {0.10: 7.77944, 0.05: 9.48773, 0.01: 13.2767, 0.001: 18.4662},
    5: {0.10: 9.23636, 0.05: 11.0705, 0.01: 15.0863, 0.001: 20.5150},
    6: {0.10: 10.6446, 0.05: 12.5916, 0.01: 16.8119, 0.001: 22.4577},
    7: {0.10: 12.0170, 0.05: 14.0671, 0.01: 18.4753, 0.001: 24.3214},
    8: {0.10: 13.3616, 0.05: 15.5073, 0.01: 20.0902, 0.001: 26.1239},
    9: {0.10: 14.6837, 0.05: 16.9189, 0.01: 21.6660, 0.001: 27.8772},
    10:{0.10: 15.9872, 0.05: 18.3070, 0.01: 23.2093, 0.001: 29.5879},
    11:{0.10: 17.2750, 0.05: 19.6751, 0.01: 24.7250, 0.001: 31.2649},
    12:{0.10: 18.5493, 0.05: 21.0261, 0.01: 26.2170, 0.001: 32.9095},
    13:{0.10: 19.8119, 0.05: 22.3620, 0.01: 27.6882, 0.001: 34.5283},
    14:{0.10: 21.0641, 0.05: 23.6848, 0.01: 29.1412, 0.001: 36.1230},
    15:{0.10: 22.3071, 0.05: 24.9958, 0.01: 30.5781, 0.001: 37.6970},
    16:{0.10: 23.5422, 0.05: 26.2962, 0.01: 31.9999, 0.001: 39.2523},
    17:{0.10: 24.7700, 0.05: 27.5871, 0.01: 33.4087, 0.001: 40.7905},
    18:{0.10: 25.9911, 0.05: 28.8693, 0.01: 34.8053, 0.001: 42.3129},
    19:{0.10: 27.2060, 0.05: 30.1435, 0.01: 36.1909, 0.001: 43.8202},
    20:{0.10: 28.4155, 0.05: 31.4104, 0.01: 37.5662, 0.001: 45.3142},
}


def find_closest_chi2(value: float) -> Dict[str, object]:
    best = {'df': None, 'alpha': None, 'crit': None, 'diff': float('inf')}
    for df, alts in CHI2_CRIT.items():
        for alpha, crit in alts.items():
            d = abs(value - crit)
            if d < best['diff']:
                best = {'df': df, 'alpha': alpha, 'crit': crit, 'diff': d}
    return best

# Вспомогательная функция для нормального распределения (Phi)
def normal_cdf(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def analyze_block_stats(block: bytes, autocorr_d: int = 1) -> Dict[str, object]:
    bits = bytes_to_bitlist(block)
    results = {}
    results['freq'] = freq_test(bits)
    results['serial'] = serial_test(bits)
    poker = poker_test(bits)
    results['poker'] = poker
    results['runs'] = runs_test(bits)
    results['autocorr'] = autocorrelation_test(bits, autocorr_d)

    # Подбор наиболее близкой хи-квадрат точки и pass/fail для X1..X4
    for name, key in [('X1', ('freq', 'X1')),
                      ('X2', ('serial', 'X2')),
                      ('X3', ('poker', 'X3')),
                      ('X4', ('runs', 'X4'))]:
        val = results[key[0]][key[1]]
        clos = find_closest_chi2(val)
        # pass если статистика меньше критического (т.е. не отвергаем H0 в верхнем хвосте)
        passed = False
        try:
            passed = val < clos['crit']
        except Exception:
            passed = False
        results[name + '_chi2_match'] = clos
        results[name + '_pass'] = passed

    # Для автокорреляции рассчитываем p-value по нормальному приближению и делаем pass по alpha=0.05
    X5 = results['autocorr']['X5']
    if math.isnan(X5):
        p = float('nan')
    else:
        z = abs(X5)
        p = 2.0 * (1.0 - normal_cdf(z))
    results['X5_info'] = {'X5': X5, 'p_value': p, 'pass_alpha_0.05': (p > 0.05 if not math.isnan(p) else False)}
    return results

# ------------------ Функции анализа BMP ------------------

def analyze_bmp24(path: str, autocorr_d: int = 5) -> Dict[str, object]:
    """Считывает BMP-файл (игнорирует 54-байтный заголовок) и выполняет все тесты
       на полном теле файла. Выводит краткую интерпретацию: пройден / не пройден.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, 'rb') as f:
        all_data = f.read()
    if len(all_data) < BMP_HEADER_SIZE:
        raise ValueError('Файл слишком мал, чтобы быть BMP.')
    body = all_data[BMP_HEADER_SIZE:]
    bits = bytes_to_bitlist(body)
    # объединяем в байтовую последовательность для analyze_block_stats
    seq_bytes = bytes(body)
    res = analyze_block_stats(seq_bytes, autocorr_d=autocorr_d)

    # Печать интерпретации
    print('
Результаты статистических тестов для файла:', path)
    # X1..X4
    for label, key in [('Частотный (X1)', 'X1'),
                       ('Последовательный (X2)', 'X2'),
                       ('Покер (X3)', 'X3'),
                       ('Серии (X4)', 'X4')]:
        val = res[label.split()[0].lower() if False else key + '_notused'] if False else None
        # возьмём значение напрямую из структуры
        if key == 'X1':
            stat = res['freq']['X1']
            match = res['X1_chi2_match']
            passed = res['X1_pass']
        elif key == 'X2':
            stat = res['serial']['X2']
            match = res['X2_chi2_match']
            passed = res['X2_pass']
        elif key == 'X3':
            stat = res['poker']['X3']
            match = res['X3_chi2_match']
            passed = res['X3_pass']
        else:
            stat = res['runs']['X4']
            match = res['X4_chi2_match']
            passed = res['X4_pass']
        sym = '✓' if passed else '✗'
        print(f"[{sym}] {label}: {stat:.5g}  (closest χ²: df={match['df']}, α={match['alpha']}, crit={match['crit']})")

    # X5
    X5 = res['autocorr']['X5']
    p = res['X5_info']['p_value']
    pass5 = res['X5_info']['pass_alpha_0.05']
    sym5 = '✓' if pass5 else '✗'
    print(f"[{sym5}] Автокорреляция (d={res['autocorr']['d']}): X5={X5:.5g}, p≈{p:.5g} (pass if p>0.05)")

    return res

# ------------------ Пример использования ------------------
if __name__ == '__main__':
    # демонстрация: шифруем случайный BMP-like тело и запускаем тесты
    key = bytes(random.getrandbits(8) for _ in range(8))
    # создадим временный BMP с случайными пикселями (заголовок 54 байта + тело)
    header = bytes([0]*BMP_HEADER_SIZE)
    body = bytes(random.getrandbits(8) for _ in range(1024))
    tmp = 'tmp_demo.bmp'
    with open(tmp, 'wb') as f:
        f.write(header + body)

    out = 'tmp_demo_ecb.bmp'
    encrypt_bmp24_ecb(tmp, out, key, analyze_after=True)

    # можно также проверить OFB
    out_ofb = 'tmp_demo_ofb.bmp'
    iv = bytes(random.getrandbits(8) for _ in range(BLOCK_SIZE))
    encrypt_bmp24_ofb(tmp, out_ofb, key, iv, analyze_after=True)

    # очистка
    try:
        os.remove(tmp)
    except Exception:
        pass
