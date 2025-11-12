import random
import math
from collections import Counter
import matplotlib.pyplot as plt

M = 26
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
ENGLISH_FREQ = {
    'A': 8.05, 'B': 1.62, 'C': 3.20, 'D': 3.65, 'E': 12.31, 'F': 2.28, 'G': 1.61, 'H': 5.14,
    'I': 7.18, 'J': 0.10, 'K': 0.52, 'L': 4.03, 'M': 2.25, 'N': 7.19, 'O': 7.94, 'P': 2.29,
    'Q': 0.20, 'R': 6.03, 'S': 6.59, 'T': 9.59, 'U': 3.10, 'V': 0.93, 'W': 2.03, 'X': 0.20,
    'Y': 1.88, 'Z': 0.09
}

def generate_key():
    while True:
        a = random.randint(1, M - 1)
        if math.gcd(a, M) == 1:
            break
    b = random.randint(0, M - 1)
    return a, b


def encrypt(text: str, key: tuple[int, int]) -> str:
    a, b = key
    result = []
    for ch in text.upper():
        if 'A' <= ch <= 'Z':
            x = ord(ch) - ord('A')
            y = (a * x + b) % M
            result.append(chr(y + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def mod_inverse(a: int, m: int) -> int:
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No inverse")


def decrypt(cipher: str, key: tuple[int, int]) -> str:
    a, b = key
    a_inv = mod_inverse(a, M)
    result = []
    for ch in cipher.upper():
        if 'A' <= ch <= 'Z':
            y = ord(ch) - ord('A')
            x = (a_inv * (y - b)) % M
            result.append(chr(x + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

def count_frequencies(text: str) -> dict[str, float]:
    c = Counter(ch for ch in text if 'A' <= ch <= 'Z')
    total = sum(c.values())
    if total == 0:
        return {}
    return {ch: (count / total) * 100 for ch, count in c.items()}

def plot_frequencies(freq: dict[str, float], title="Frequency Histogram"):
    chars = list(freq.keys())
    values = list(freq.values())
    plt.figure(figsize=(10, 5))
    plt.bar(chars, values)
    plt.title(title)
    plt.xlabel("Letter")
    plt.ylabel("Frequency (%)")
    plt.tight_layout()
    plt.savefig(f"{title.replace(' ', '_')}.png")  # сохраняем в файл

def frequency_decrypt(cipher: str) -> str:
    freq_cipher = count_frequencies(cipher)
    # Сортируем буквы шифра по частоте
    sorted_cipher = sorted(freq_cipher, key=lambda ch: freq_cipher[ch], reverse=True)
    # Сопоставляем с таблицей английских частот
    mapping = {enc: dec for enc, dec in zip(sorted_cipher, ENGLISH_FREQ_ORDER)}
    return ''.join(mapping.get(ch, ch) for ch in cipher)

def compare_texts(original: str, decrypted: str) -> float:
    o = [ch for ch in original.upper() if 'A' <= ch <= 'Z']
    d = [ch for ch in decrypted.upper() if 'A' <= ch <= 'Z']
    total = min(len(o), len(d))
    errors = sum(o[i] != d[i] for i in range(total))
    return (errors / total) * 100 if total else 0

import csv 
def load_top_words(filename: str, top_n: int) -> list[str]:
    words = [] 
    with open(filename, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for i, row in enumerate(reader):
            if i >= top_n:
                break
            word = row['word'].upper()
            words.append(word)
    return words


if __name__ == "__main__":
    error_rates = []
    for i in range(333333, 333334):
        text = " ".join(load_top_words("unigram_freq.csv", i))
        # print(f"text: {text}")

        key = generate_key()
        print(f"Generated key: {key}")

        encrypted = encrypt(text, key)
        decrypted_true = decrypt(encrypted, key)

        # print("\nEncrypted:\n", encrypted)
        freq = count_frequencies(encrypted)
        print("\nFrequencies:", freq)

        plot_frequencies(freq, "Encrypted Text Frequencies")

        guessed = frequency_decrypt(encrypted)
        # print("\nGuessed (frequency) decryption:\n", guessed)

        error = compare_texts(text, guessed)
        print(f"\nError rate: {error:.2f}%")
        error_rates.append(error)
        # print("\n(True decrypted for reference):\n", decrypted_true)

    print(error_rates)

    print(min(error_rates))
