<div align="center">
  <img src="app.png" width="92" alt="3DES File Encryptor" />
  <h1>3DES File Encryptor</h1>
  <p><b>A modern desktop app for encrypting and decrypting any file or folder with Triple DES and authenticated integrity protection.</b></p>

  ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
  ![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
  ![Built with CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-3D7BFC.svg)
</div>

---

3DES File Encryptor secures any file or whole folder — documents, images, archives —
using **Triple DES (DESede)** in CBC mode, hardened with **HMAC-SHA256** authentication.
It pairs a clean, themed interface with a security-first core: encrypt-then-MAC,
key separation via HKDF, fresh random IVs, and constant-time verification.

## Screenshot

![App screenshot](docs/screenshot.png)

## Features

- **Encrypts files and folders** — any file type (TXT, PDF, DOCX, JPG, PNG, ZIP…); folders are zipped, then encrypted, and restored on decrypt.
- **Authenticated encryption** — HMAC-SHA256 detects a wrong key, corruption, or tampering *before* decrypting.
- **Keying Option 1 (3TDEA)** — three independent 8-byte odd-parity DES keys (168-bit), generated from the OS true-entropy CSPRNG.
- **Secure key management** — save, load, and copy keys as Base64 `.key` files.
- **Modern UI** — dark/light theme, masked key field with show/copy, file and folder pickers, live progress, colour-coded status.
- **Responsive** — encryption runs off the UI thread, so large files never freeze the window.
- **Tested** — 17 automated unit tests (dynamic) plus a documented static-testing checklist.
- **Ships as a single executable** — packaged with PyInstaller, custom icon included.

## Tech stack

Python · CustomTkinter (UI) · PyCryptodome (cryptography) · unittest (testing) · PyInstaller (packaging)

## How it works

Each encrypted file is a self-contained, authenticated container:

```
+---------+----------+---------+----------+--------------------+
| MAGIC   | VERSION  | IV      | HMAC tag | ciphertext         |
| 4 bytes | 1 byte   | 8 bytes | 32 bytes | variable           |
+---------+----------+---------+----------+--------------------+
```

Design decisions that go beyond just calling a crypto library:

- **Encrypt-then-MAC** — the HMAC tag authenticates `MAGIC || VERSION || IV || ciphertext`, and is verified *before* any decryption, so padding-oracle attacks aren't possible.
- **Key separation** — the encryption key and the HMAC key are never the same material; the MAC key is derived with **HKDF-SHA256**.
- **Fresh random IV** per operation — encrypting the same file twice produces different ciphertext.
- **Constant-time verification** prevents timing side channels.
- **PKCS#7 padding** with strict validation on unpad.
- **File or folder** — the first byte of the decrypted payload flags whether the original was a single file or a zipped folder, so one container format handles both and the flag is itself encrypted and authenticated.
- **Keys** use Keying Option 1 (three independent keys, 168-bit), each an 8-byte odd-parity DES key drawn from the OS CSPRNG (`get_random_bytes`), which is seeded from the system's true-entropy pool. Degenerate keys are rejected.

> **On the choice of 3DES:** Triple DES is a legacy cipher — NIST disallowed it for new
> applications after 2023 (SP 800-131A Rev. 2) due to its 64-bit block size (Sweet32) and
> performance. **AES-256** is the modern choice. 3DES is implemented here deliberately as the
> project's subject; the surrounding construction otherwise follows current best practice.

## Getting started

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/<repo>.git
cd <repo>
pip install -r requirements.txt
python main.py
```

> Tkinter ships with the standard Python installer on Windows and macOS. On some Linux
> distros, install it with `sudo apt install python3-tk`.

### Usage

1. **Generate** a key (or **Load** an existing one), then **Save** it — you need the same key to decrypt later.
2. Click **Choose file…** or **Choose folder…**.
3. **Encrypt** → pick where to save the `.enc` file. To recover it, load the same key, select the `.enc`, and **Decrypt** (a folder restores to a destination you pick).

## Testing

**Dynamic testing** (executes the code):

```bash
python -m unittest -v test_crypto.py
```

17 unit tests cover round-trip correctness (text, binary, empty, block-aligned, ~1 MB),
file and folder round-trips, wrong-key rejection, tamper/corruption detection, malformed
input, key uniqueness, key save/load, and IV randomness. They also run automatically on
every push via GitHub Actions.

**Static testing** (reviews the code without running it) — security analysis with Bandit,
plus Pylint/Flake8 and a manual code-review checklist. Full procedure and the complete
list of test cases (static + dynamic + manual GUI scenarios) are in
[TEST_DOCUMENTATION.md](TEST_DOCUMENTATION.md).

## Build a standalone executable

```bash
# Windows  (use ; in --add-data)
python -m PyInstaller --noconfirm --onefile --windowed --name "3DES-File-Encryptor" --icon app.ico --add-data "app.ico;." --collect-all customtkinter main.py

# macOS / Linux  (use : in --add-data)
python -m PyInstaller --noconfirm --onefile --windowed --name "3DES-File-Encryptor" --icon app.ico --add-data "app.ico:." --collect-all customtkinter main.py
```

The binary is written to `dist/`. PyInstaller does not cross-compile — build on Windows for a `.exe`, on macOS for a macOS binary.

## Project structure

```
.
├── main.py            # entry point
├── gui.py             # CustomTkinter interface
├── crypto_core.py     # 3DES + HMAC encryption/decryption (file & folder)
├── key_manager.py     # key generation, save/load
├── test_crypto.py     # unit tests (dynamic)
├── TEST_DOCUMENTATION.md  # static + dynamic test cases
├── app.ico / app.png  # application icon
└── requirements.txt
```

## License

Released under the [MIT License](LICENSE).

---

<sub>Originally built for my M.Sc. Software Engineering (Software Security) coursework, then refined into a standalone tool.</sub>
