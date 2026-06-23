"""
test_crypto.py
==============
Unit tests for the 3DES File Encryptor core (dynamic testing, 17 cases).

Run any of:
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
        data = b"A" * 64
        blob = crypto_core.encrypt_bytes(data, self.key)
        self.assertEqual(crypto_core.decrypt_bytes(blob, self.key), data)

    def test_05_roundtrip_large(self):
        data = os.urandom(1_000_000)
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
        blob[-1] ^= 0x01
        with self.assertRaises(crypto_core.CryptoError):
            crypto_core.decrypt_bytes(bytes(blob), self.key)

    def test_08_tampered_iv_fails(self):
        blob = bytearray(crypto_core.encrypt_bytes(b"important data", self.key))
        blob[6] ^= 0x01
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
        b1 = crypto_core.encrypt_bytes(data, self.key)
        b2 = crypto_core.encrypt_bytes(data, self.key)
        self.assertNotEqual(b1, b2)
        self.assertEqual(crypto_core.decrypt_bytes(b1, self.key), data)
        self.assertEqual(crypto_core.decrypt_bytes(b2, self.key), data)

    # ---------------------------------------------------- file round-trip
    def test_16_file_path_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "plain.bin")
            enc = os.path.join(d, "plain.enc")
            content = os.urandom(4096)
            with open(src, "wb") as f:
                f.write(content)
            self.assertEqual(crypto_core.encrypt_path(src, enc, self.key), "file")
            kind, data = crypto_core.decrypt_blob(enc, self.key)
            self.assertEqual(kind, "file")
            self.assertEqual(data, content)

    # -------------------------------------------------- folder round-trip
    def test_17_folder_path_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, "proj")
            os.makedirs(os.path.join(folder, "sub"))
            with open(os.path.join(folder, "a.txt"), "wb") as f:
                f.write(b"A" * 100)
            payload = os.urandom(512)
            with open(os.path.join(folder, "sub", "b.bin"), "wb") as f:
                f.write(payload)
            enc = os.path.join(d, "proj.enc")
            self.assertEqual(crypto_core.encrypt_path(folder, enc, self.key),
                             "folder")
            kind, data = crypto_core.decrypt_blob(enc, self.key)
            self.assertEqual(kind, "folder")
            dest = os.path.join(d, "out")
            crypto_core.extract_zip_bytes(data, dest)
            with open(os.path.join(dest, "proj", "a.txt"), "rb") as f:
                self.assertEqual(f.read(), b"A" * 100)
            with open(os.path.join(dest, "proj", "sub", "b.bin"), "rb") as f:
                self.assertEqual(f.read(), payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
