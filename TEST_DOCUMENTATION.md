# Test Documentation — 3DES File Encryptor

This document covers the **static testing** and **dynamic testing** of the
application, as required by the project brief.

- **Static testing** = reviewing the source code *without executing it* (code
  review + automated static analysis).
- **Dynamic testing** = *executing* the program with many inputs and checking
  the actual results against the expected results.

---

## 1. Static testing

### 1.1 Automated static analysis

Run from the project folder (install the tools once with
`pip install bandit pylint flake8`):

| Tool | Purpose | Command |
|------|---------|---------|
| Bandit | Security-focused static analysis for Python | `bandit -r .` |
| Pylint | Code quality, errors, conventions | `pylint crypto_core.py key_manager.py gui.py main.py` |
| Flake8 | Style and lint checks | `flake8 .` |

Record the tool output (or a screenshot of a clean run) in the report.

### 1.2 Manual code-review checklist

| # | Review item | Result |
|---|-------------|--------|
| S1 | No hard-coded keys, passwords, or secrets in the source | Pass |
| S2 | Key material comes from the OS CSPRNG (`get_random_bytes`), not `random` | Pass |
| S3 | No use of `eval`, `exec`, or `os.system` / shell calls | Pass |
| S4 | 3DES uses CBC mode with a random IV (never ECB, never a fixed IV) | Pass |
| S5 | Integrity verified before decryption (Encrypt-then-MAC) | Pass |
| S6 | HMAC comparison is constant-time (`HMAC.verify`, not `==`) | Pass |
| S7 | Encryption key and MAC key are separated (HKDF-SHA256) | Pass |
| S8 | Keys are parity-adjusted and degenerate keys are rejected | Pass |
| S9 | All file/key inputs are validated; errors raise `CryptoError` | Pass |
| S10 | Exceptions are handled; the GUI never crashes on bad input | Pass |
| S11 | Code is modular (crypto / key management / UI separated) | Pass |
| S12 | Consistent naming, docstrings on public functions | Pass |

---

## 2. Dynamic testing

### 2.1 Automated unit tests

Run: `python -m unittest -v test_crypto.py` → expected result: **17 tests, OK.**

| # | Test case | Input | Expected result |
|---|-----------|-------|-----------------|
| T01 | Encrypt/decrypt short text | `b"Hello, Software Security!"` | Output == input |
| T02 | Encrypt/decrypt empty data | `b""` | Output == input |
| T03 | Encrypt/decrypt binary data | all 256 byte values ×4 | Output == input |
| T04 | Block-aligned data (multiple of 8) | 64 bytes | Output == input |
| T05 | Large data | ~1 MB random | Output == input |
| T06 | Wrong key rejected | decrypt with a different key | Raises `CryptoError` |
| T07 | Tampered ciphertext rejected | flip 1 bit in ciphertext | Raises `CryptoError` |
| T08 | Tampered IV rejected | flip 1 bit in IV | Raises `CryptoError` |
| T09 | Truncated file rejected | first 10 bytes only | Raises `CryptoError` |
| T10 | Bad magic header rejected | corrupt magic bytes | Raises `CryptoError` |
| T11 | Unsupported version rejected | set version byte = 99 | Raises `CryptoError` |
| T12 | Key length | generated key | Exactly 24 bytes |
| T13 | Key uniqueness | two generated keys | Different each time |
| T14 | Key save/load round-trip | save then load `.key` | Loaded == original |
| T15 | Random IV | encrypt same data twice | Different ciphertexts, both decrypt correctly |
| T16 | File round-trip (path API) | 4 KB file | Restored bytes == original; type = file |
| T17 | Folder round-trip (path API) | nested folder | All files + structure restored; type = folder |

### 2.2 Manual GUI test scenarios

| # | Scenario | Steps | Expected result |
|---|----------|-------|-----------------|
| G1 | Encrypt/decrypt a text file | choose `.txt` → Encrypt → Decrypt with same key | File opens identical |
| G2 | Other file types | repeat G1 with `.pdf`, `.docx`, `.jpg`, `.png` | All open correctly after decrypt |
| G3 | Encrypt/decrypt a folder | Choose folder → Encrypt → Decrypt → pick output dir | Whole folder restored with sub-folders |
| G4 | Wrong key | encrypt, then Decrypt with a different key | Clear error: wrong key / corrupted |
| G5 | Tampered file | edit a byte of the `.enc` in a hex editor → Decrypt | Rejected with integrity error |
| G6 | Empty file | encrypt a 0-byte file → Decrypt | Restored 0-byte file |
| G7 | Large file | encrypt a ~100 MB file | Completes; progress bar shows; window stays responsive |
| G8 | Wrong input to Decrypt | select a normal (non-`.enc`) file → Decrypt | Rejected: unrecognized format |
| G9 | No key | press Encrypt with no key | Prompt to generate/load a key |
| G10 | No selection | press Encrypt with nothing chosen | Prompt to choose a file or folder |
| G11 | Save / load key | Generate → Save → restart → Load | Same key loads back |
| G12 | Executable | run the built `.exe` and repeat G1 | Behaves the same as `python main.py` |

Capture screenshots of representative scenarios (G1, G3, G4, G7, G12) for the
report.
