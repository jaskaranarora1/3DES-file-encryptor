"""
crypto_core.py
==============
Core cryptographic operations for the 3DES File Encryptor.

Authenticated encryption of any file OR folder using Triple DES
(3DES / DESede) in CBC mode with PKCS#7 padding, plus HMAC-SHA256
integrity protection (Encrypt-then-MAC).

Encrypted container (.enc) layout:

    +---------+----------+---------+----------+--------------------+
    | MAGIC   | VERSION  | IV      | HMAC tag | ciphertext         |
    | 4 bytes | 1 byte   | 8 bytes | 32 bytes | variable           |
    +---------+----------+---------+----------+--------------------+

The first byte of the *decrypted* payload is a type tag (0 = file,
1 = zipped folder), so the container format itself is unchanged and the
type marker is protected by both encryption and the HMAC. Folders are
zipped in memory before encryption and re-extracted on decryption.

The HMAC tag authenticates MAGIC || VERSION || IV || ciphertext, so a
wrong key, corruption, or tampering is detected before decryption. The
MAC key is derived from the master key with HKDF-SHA256 (key separation).
"""

import io
import os
import zipfile

# PyCryptodome is the actively maintained fork of pyCrypto (same import
# namespace). Bandit B413 incorrectly flags it as the deprecated pyCrypto.
from Crypto.Cipher import DES3              # nosec B413
from Crypto.Hash import HMAC, SHA256        # nosec B413
from Crypto.Protocol.KDF import HKDF       # nosec B413
from Crypto.Random import get_random_bytes  # nosec B413
from Crypto.Util.Padding import pad, unpad  # nosec B413

# --- container constants ---
MAGIC = b"3DEF"
VERSION = 1
IV_SIZE = 8
TAG_SIZE = 32
HEADER_SIZE = len(MAGIC) + 1 + IV_SIZE + TAG_SIZE  # 45 bytes

# --- payload type tags (first byte of the decrypted payload) ---
TYPE_FILE = 0
TYPE_FOLDER = 1


class CryptoError(Exception):
    """Raised when an encryption or decryption operation fails."""
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise CryptoError("Key must be raw bytes.")
    if len(key) not in (16, 24):
        raise CryptoError("3DES key must be 16 or 24 bytes long.")


def _derive_mac_key(master_key: bytes) -> bytes:
    """Derive a separate 32-byte HMAC key from the master key (HKDF-SHA256)."""
    return HKDF(master_key, 32, None, SHA256, context=b"3DES-Encryptor-MAC-v1")


# ---------------------------------------------------------------------------
# Byte-level authenticated encryption (the verified core)
# ---------------------------------------------------------------------------
def encrypt_bytes(plaintext: bytes, master_key: bytes) -> bytes:
    """Encrypt raw bytes and return a self-contained authenticated blob."""
    _validate_key(master_key)
    mac_key = _derive_mac_key(master_key)

    iv = get_random_bytes(IV_SIZE)
    cipher = DES3.new(master_key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))

    preamble = MAGIC + bytes([VERSION]) + iv
    tag = HMAC.new(mac_key, preamble + ciphertext, digestmod=SHA256).digest()
    return preamble + tag + ciphertext


def decrypt_bytes(blob: bytes, master_key: bytes) -> bytes:
    """Verify integrity and decrypt a blob produced by ``encrypt_bytes``."""
    _validate_key(master_key)

    if len(blob) < HEADER_SIZE:
        raise CryptoError("File is too small to be a valid encrypted file.")
    if blob[:4] != MAGIC:
        raise CryptoError("Unrecognized file format (bad magic header).")

    version = blob[4]
    if version != VERSION:
        raise CryptoError(f"Unsupported file version: {version}.")

    iv = blob[5:5 + IV_SIZE]
    tag = blob[5 + IV_SIZE:HEADER_SIZE]
    ciphertext = blob[HEADER_SIZE:]
    preamble = blob[:5 + IV_SIZE]

    mac_key = _derive_mac_key(master_key)
    try:
        HMAC.new(mac_key, preamble + ciphertext, digestmod=SHA256).verify(tag)
    except ValueError:
        raise CryptoError(
            "Integrity check failed: wrong key, or the file is corrupted "
            "or has been tampered with."
        )

    cipher = DES3.new(master_key, DES3.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(ciphertext), DES3.block_size)
    except ValueError:
        raise CryptoError("Decryption failed (invalid padding).")


# ---------------------------------------------------------------------------
# Folder zipping helpers
# ---------------------------------------------------------------------------
def _zip_folder_to_bytes(folder_path: str) -> bytes:
    """Zip an entire folder (recursively) into an in-memory archive."""
    base = os.path.basename(os.path.normpath(folder_path))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(folder_path):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, folder_path)
                zf.write(full, os.path.join(base, rel))
    return buf.getvalue()


def extract_zip_bytes(data: bytes, dest_dir: str) -> None:
    """Extract a zipped-folder payload into ``dest_dir``."""
    os.makedirs(dest_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest_dir)


# ---------------------------------------------------------------------------
# Path-level API (file OR folder) used by the GUI
# ---------------------------------------------------------------------------
def encrypt_path(in_path: str, out_path: str, master_key: bytes) -> str:
    """
    Encrypt a file or a folder into a single ``.enc`` container.
    Folders are zipped first. Returns "file" or "folder".
    """
    if os.path.isdir(in_path):
        payload = bytes([TYPE_FOLDER]) + _zip_folder_to_bytes(in_path)
        kind = "folder"
    else:
        with open(in_path, "rb") as f:
            payload = bytes([TYPE_FILE]) + f.read()
        kind = "file"
    blob = encrypt_bytes(payload, master_key)
    with open(out_path, "wb") as f:
        f.write(blob)
    return kind


def decrypt_blob(in_path: str, master_key: bytes):
    """
    Decrypt a ``.enc`` container and return ``(kind, data)`` where ``kind`` is
    "file" or "folder" and ``data`` is the original file bytes or the zipped
    folder bytes. The caller decides where to write/extract it.
    """
    with open(in_path, "rb") as f:
        blob = f.read()
    payload = decrypt_bytes(blob, master_key)
    if not payload:
        raise CryptoError("Decrypted payload is empty or invalid.")
    ptype = payload[0]
    data = payload[1:]
    if ptype == TYPE_FOLDER:
        return "folder", data
    if ptype == TYPE_FILE:
        return "file", data
    raise CryptoError("Unknown payload type tag.")