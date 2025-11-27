import os

from feal_OFB import (
    encrypt_bmp24_ofb,
    parse_hex_key,
)

from tests import run_all_tests, correlation_rgb

def bytes_to_pixels(data):
    pixels = []
    length = len(data) - (len(data) % 3)
    for i in range(0, length, 3):
        b = data[i]
        g = data[i+1]
        r = data[i+2]
        pixels.append((r, g, b))
    return pixels

def test_ecb_ofb_with_stats(BMP="image2.bmp"):
    key = parse_hex_key("0011223344556677")
    iv = bytes.fromhex("aea8c551376fc6e0")

    base, ext = os.path.splitext(BMP)

    paths = {
        "ecb_enc": f"{base}_ecb_cipher.bmp",
        "ecb_dec": f"{base}_ecb_decrypted.bmp",
        "ofb_enc": f"{base}_ofb_cipher.bmp",
        "ofb_dec": f"{base}_ofb_decrypted.bmp",
    }

    print("Шифрование")
    encrypt_bmp24_ofb(BMP, paths["ofb_enc"], key, iv)

    with open(paths["ofb_enc"], "rb") as f:
        ofb_bytes = f.read()[54:]

    with open('image2.bmp', "rb") as f:
        orig_bytes = f.read()[54:]

    pixels_ofb = bytes_to_pixels(ofb_bytes)
    pixels_orig = bytes_to_pixels(orig_bytes)

    corr = correlation_rgb(pixels_orig, pixels_ofb)
    print(corr)
    
    # print("Статистические тесты")
    # run_all_tests(ofb_bytes)

    return paths


if __name__ == "__main__":
    test_ecb_ofb_with_stats("image2.bmp")
