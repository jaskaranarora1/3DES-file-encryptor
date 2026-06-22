"""
key_manager.py
==============
Secure random key generation and key-file persistence for 3DES.

A 3-key Triple DES key is 24 bytes (192 bits, 168 effective). Keys are
stored on disk as Base64 text so they are easy to copy, back up, and load.
"""

import base64

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

KEY_SIZE = 24  # 3-key Triple DES


def generate_key() -> bytes:
    """
    Generate a cryptographically secure, parity-adjusted 3-key 3DES key.

    ``get_random_bytes`` draws from the OS CSPRNG. ``adjust_key_parity``
    sets the DES parity bits and rejects keys that degenerate to single
    DES (k1 == k2 == k3); in that rare case we simply draw again.
    """
    while True:
        try:
            return DES3.adjust_key_parity(get_random_bytes(KEY_SIZE))
        except ValueError:
            continue


def key_to_b64(key: bytes) -> str:
    """Encode a raw key as a Base64 string."""
    return base64.b64encode(key).decode("ascii")


def b64_to_key(text: str) -> bytes:
    """Decode a Base64 string back into a raw key, validating its length."""
    key = base64.b64decode(text.strip())
    if len(key) not in (16, 24):
        raise ValueError("Decoded key is not 16 or 24 bytes.")
    return key


def save_key(key: bytes, path: str) -> None:
    """Write a key to a file as Base64 text."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(key_to_b64(key))


def load_key(path: str) -> bytes:
    """Read a Base64-encoded key from a file and validate it."""
    with open(path, "r", encoding="utf-8") as f:
        data = f.read().strip()
    try:
        key = base64.b64decode(data)
    except Exception:
        raise ValueError("Key file is not valid Base64.")
    if len(key) not in (16, 24):
        raise ValueError("Key file does not contain a valid 16- or 24-byte key.")
    return key
