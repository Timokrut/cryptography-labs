import os

from tests import run_all_tests

def test_ofb_with_stats(BMP="image2.bmp"):
    base, ext = os.path.splitext(BMP)

    paths = {
        "ofb_enc": f"{base}_ofb_cipher.bmp",
        "ofb_dec": f"{base}_ofb_decrypted.bmp",
    }

    # encrypt_bmp24_ofb(BMP, paths["ofb_enc"], key, iv)

    with open(paths["ofb_enc"], "rb") as f:
        ofb_bytes = f.read()[54:]

    print("\nOFB")
    run_all_tests(ofb_bytes)

    return paths

if __name__ == "__main__":
    test_ofb_with_stats("image2.bmp")
