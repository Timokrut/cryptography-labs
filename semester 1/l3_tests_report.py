def bytes_to_bits(bs: bytes):
    bits = []
    for b in bs:
        for i in range(8):
            bits.append((b >> (7-i)) & 1)
    return bits

CHI2_TABLE = {
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

def closest_chi2_match(value: float) -> dict:
    best = None
    for df, row in CHI2_TABLE.items():
        for alpha, crit in row.items():
            diff = abs(value - crit)
            if best is None or diff < best["diff"]:
                best = {
                    "df": df,
                    "alpha": alpha,
                    "crit": crit,
                    "diff": diff
                }
    return best

# X1 — Частотный тест
def bit_frequency_test(bits):
    n = len(bits)
    n1 = sum(bits)
    n0 = n - n1
    X1 = ((n0 - n1)**2) / n
    return X1

# X2 — Последовательный тест
from collections import Counter

def sequential_test(bits):
    n = len(bits)
    n0 = bits.count(0)
    n1 = bits.count(1)

    n00 = 0
    n01 = 0
    n10 = 0
    n11 = 0
    for i in range(n - 1):
        pair = (bits[i], bits[i+1])
        if pair == (0, 0):
            n00 += 1
        elif pair == (0, 1):
            n01 += 1
        elif pair == (1, 0):
            n10 += 1
        elif pair == (1, 1):
            n11 += 1

    X2 = (4 / (n - 1)) * (n00**2 + n01**2 + n10**2 + n11**2) - (2 / n) * (n0**2 + n1**2) + 1
    return X2

# X3 — Покер-тест
def poker_test(bits):
    n = len(bits)

    best_m = None
    for m in range(1, 5):
        k = n // m
        if k >= 5*(2**m):
            best_m = m

    if best_m is None:
        return None

    m = best_m
    k = n // m

    blocks = []
    idx = 0
    for _ in range(k):
        v = 0
        for i in range(m):
            v = (v << 1) | bits[idx]
            idx += 1
        blocks.append(v)

    cnt = Counter(blocks)

    sum_sq = sum(count ** 2 for count in cnt.values())

    X3 = (2 ** m / k) * sum_sq - k

    return {"m": m, "k": k, "X3": X3}

# X4 — Тест серий
def runs_test(bits):
    n = len(bits)
    runs = []
    cur = bits[0]
    ln = 1

    for b in bits[1:]:
        if b == cur:
            ln += 1
        else:
            runs.append((cur, ln))
            cur = b
            ln = 1
    runs.append((cur, ln))

    L = max(length for _, length in runs)

    E = {}
    for i in range(1, L+1):
        E[i] = (n - i + 3) / 2**(i+2)
    
    valid = [i for i in E if E[i] >= 5]
    k = max(valid)

    if not valid:
        return None

    B = {i:0 for i in valid}
    G = {i:0 for i in valid}

    for val, ln in runs:
        if ln in valid:
            if val == 1:
                B[ln] += 1
            else:
                G[ln] += 1
    
    X4 = 0
    for i in valid:
        X4 += (B[i]-E[i])**2/E[i] + (G[i]-E[i])**2/E[i]

    df = 2*len(valid) - 2

    return {"X4": X4, "df": df}

# X5 — Автокорреляция
def autocorrelation_test(bits, d):
    n = len(bits)
    
    A = 0
    for i in range(n - d):
        if bits[i] != bits[i + d]:
            A += 1 # -> XOR = 1
    
    X5 = 2 * (A - (n - d) / 2)**2 / (n - d)
    return X5

def evaluate_result(value, crit, alpha, invert=False):
    if invert:
        if value < crit:
            return "ХОРОШО"
        else:
            return "ПЛОХО"
    else:
        if value < crit:
            return "ХОРОШО"
        else:
            return "ПЛОХО"

def run_all_tests(data: bytes):
    bits = bytes_to_bits(data)
    # X1 — частотный тест (df=1)
    X1 = bit_frequency_test(bits)
    chi2_info = closest_chi2_match(X1)
    eval_res = evaluate_result(X1, chi2_info["crit"], chi2_info["alpha"])
    print(f"X1 (частотный): {X1:.6f}, df={chi2_info['df']}, alpha={chi2_info['alpha']}, crit={chi2_info['crit']:.4f} -> {eval_res}")

    # X2 — последовательный тест (df=3)
    X2 = sequential_test(bits)
    chi2_info = closest_chi2_match(X2)
    eval_res = evaluate_result(X2, chi2_info["crit"], chi2_info["alpha"])
    print(f"X2 (последовательный): {X2:.6f}, df={chi2_info['df']}, alpha={chi2_info['alpha']}, crit={chi2_info['crit']:.4f} -> {eval_res}")

    # X3 — покер-тест
    X3 = poker_test(bits)
    if X3:
        chi2_info = closest_chi2_match(X3['X3'])
        eval_res = evaluate_result(X3['X3'], chi2_info["crit"], chi2_info["alpha"])
        print(f"X3 (покер, m={X3['m']}, k={X3['k']}): {X3['X3']:.6f}, df={chi2_info['df']}, alpha={chi2_info['alpha']}, crit={chi2_info['crit']:.4f} -> {eval_res}")
    else:
        print("X3: недостаточно данных")

    # X4 — тест серий
    X4 = runs_test(bits)
    if X4:
        chi2_info = closest_chi2_match(X4['X4'])
        eval_res = evaluate_result(X4['X4'], chi2_info["crit"], chi2_info["alpha"])
        print(f"X4 (серии): {X4['X4']:.6f}, df={X4['df']}, alpha={chi2_info['alpha']}, crit={chi2_info['crit']:.4f} -> {eval_res}")
    else:
        print("X4: недостаточно данных")

    # X5 — автокорреляция (df=1)
    for d in [1, 4, 8]:
        if len(bits) > d:
            X5 = autocorrelation_test(bits, d)
            chi2_info = closest_chi2_match(X5)
            eval_res = evaluate_result(X5, chi2_info["crit"], chi2_info["alpha"])
            print(f"X5(d={d}): {X5:.6f}, df={chi2_info['df']}, alpha={chi2_info['alpha']}, crit={chi2_info['crit']:.4f} -> {eval_res}")
