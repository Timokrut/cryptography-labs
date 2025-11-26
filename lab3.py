from PIL import Image
import os

from feal_OFB import (
    encrypt_bmp24_ecb,
    decrypt_bmp24_ecb,
    encrypt_bmp24_ofb,
    decrypt_bmp24_ofb,
    parse_hex_key,
    random_iv,
    count_different_pixels
)

from tests import run_all_tests

def test_ecb_ofb_with_stats(BMP="image2.bmp"):
    key = parse_hex_key("0011223344556677")
    iv = bytes.fromhex("aea8c551376fc6e0")
    # iv = random_iv()

    base, ext = os.path.splitext(BMP)

    paths = {
        "ecb_enc": f"{base}_ecb_cipher.bmp",
        "ecb_dec": f"{base}_ecb_decrypted.bmp",
        "ofb_enc": f"{base}_ofb_cipher.bmp",
        "ofb_dec": f"{base}_ofb_decrypted.bmp",
    }

    print("\n=== ШИФРОВАНИЕ ECB ===")
    # encrypt_bmp24_ecb(BMP, paths["ecb_enc"], key)
    # decrypt_bmp24_ecb(paths["ecb_enc"], paths["ecb_dec"], key)

    print("\n=== ШИФРОВАНИЕ OFB ===")
    # encrypt_bmp24_ofb(BMP, paths["ofb_enc"], key, iv)
    # decrypt_bmp24_ofb(paths["ofb_enc"], paths["ofb_dec"], key, iv)

    # ============================================================
    #                       ЧТЕНИЕ ШИФРОТЕКСТОВ
    # ============================================================

    print("\n=== ЧТЕНИЕ ШИФРОТЕКСТОВ ===")
    with open(paths["ecb_enc"], "rb") as f:
        ecb_bytes = f.read()[54:]

    with open(paths["ofb_enc"], "rb") as f:
        ofb_bytes = f.read()[54:]

    # ============================================================
    #                СТАТИСТИЧЕСКИЕ ТЕСТЫ X1–X5
    # ============================================================

    print("\n\n==================================================")
    print("====   СТАТИСТИКА ДЛЯ ECB-ШИФРОТЕКСТА   ====")
    print("==================================================")
    run_all_tests(ecb_bytes)

    print("\n==================================================")
    print("====   СТАТИСТИКА ДЛЯ OFB-ШИФРОТЕКСТА   ====")
    print("==================================================")
    run_all_tests(ofb_bytes)

    return paths


if __name__ == "__main__":
    test_ecb_ofb_with_stats("image2.bmp")
