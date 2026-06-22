"""
test_crypto.py
==============
Unit tests for the 3DES File Encryptor core (16 test cases).

Run any of:
    python -m unittest test_crypto.py
    python -m unittest -v test_crypto.py
    python test_crypto.py
"""

import os
import tempfile
import unittest

import crypto_core
import key_manager


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.key = key_manager.generate_key()

    # ---------------------------------------------- round-trip correctness
    def test_01_roundtrip_text(self):
        data = b"Hello, Software Security!"
        blob = crypto_core.encrypt_bytes(data, self.key)
        self.assertEqual(crypto_core.decrypt_bytes(blob, self.key), data)

    def test_02_roundtrip_empty(self):
        data = b""
        blob = crypto_core.encrypt_bytes(data, self.key)
        self.assertEqual(crypto_core.decrypt_bytes(blob, self.key), data)

    def test_03_roundtrip_binary(self):
        data = bytes(range(256)) * 4
        blob = crypto_core.encrypt_bytes(data, self.key)
        self.assertEqual(crypto_core.decrypt_bytes(blob, self.key), data)

    def test_04_roundtrip_block_aligned(self):
        data = b"A" * 64  # exact multiple of the 8-byte block size
        blob = crypto_core.encrypt_bytes(data, self.key)
        self.assertEqual(crypto_core.decrypt_bytes(blob, self.key), data)

    def test_05_roundtrip_large(self):
        data = os.urandom(1_000_000)  # ~1 MB
        blob = crypto_core.encrypt_bytes(data, self.key)
        self.assertEqual(crypto_core.decrypt_bytes(blob, self.key), data)

    # ------------------------------------------------- security properties
    def test_06_wrong_key_fails(self):
        blob = crypto_core.encrypt_bytes(b"secret", self.key)
        other = key_manager.generate_key()
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(blob, other)

    def test_07_tampered_ciphertext_fails(self):
        blob = bytearray(crypto_core.encrypt_bytes(b"important data", self.key))
        blob[-1] ^= 0x01  # flip a bit in the ciphertext
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(bytes(blob), self.key)

    def test_08_tampered_iv_fails(self):
        blob = bytearray(crypto_core.encrypt_bytes(b"important data", self.key))
        blob[6] ^= 0x01  # flip a bit inside the IV
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(bytes(blob), self.key)

    def test_09_truncated_fails(self):
        blob = crypto_core.encrypt_bytes(b"data", self.key)
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(blob[:10], self.key)

    def test_10_bad_magic_fails(self):
        blob = bytearray(crypto_core.encrypt_bytes(b"data", self.key))
        blob[0] ^= 0xFF
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(bytes(blob), self.key)

    def test_11_bad_version_fails(self):
        blob = bytearray(crypto_core.encrypt_bytes(b"data", self.key))
        blob[4] = 99
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(bytes(blob), self.key)

    # -------------------------------------------------------- key handling
    def test_12_key_length(self):
        self.assertEqual(len(self.key), 24)

    def test_13_keys_unique(self):
        self.assertNotEqual(key_manager.generate_key(),
                            key_manager.generate_key())

    def test_14_key_save_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.key")
            key_manager.save_key(self.key, path)
            self.assertEqual(key_manager.load_key(path), self.key)

    # -------------------------------------------------------- IV randomness
    def test_15_random_iv_unique_ciphertexts(self):
        data = b"same plaintext"
        blob1 = crypto_core.encrypt_bytes(data, self.key)
        blob2 = crypto_core.encrypt_bytes(data, self.key)
        self.assertNotEqual(blob1, blob2)  # different random IV each time
        self.assertEqual(crypto_core.decrypt_bytes(blob1, self.key), data)
        self.assertEqual(crypto_core.decrypt_bytes(blob2, self.key), data)

    # ------------------------------------------------------- file handling
    def test_16_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "plain.txt")
            enc = os.path.join(d, "plain.txt.enc")
            dec = os.path.join(d, "plain_out.txt")
            content = b"File-based round-trip test.\n" * 100
            with open(src, "wb") as f:
                f.write(content)
            crypto_core.encrypt_file(src, enc, self.key)
            crypto_core.decrypt_file(enc, dec, self.key)
            with open(dec, "rb") as f:
                self.assertEqual(f.read(), content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
