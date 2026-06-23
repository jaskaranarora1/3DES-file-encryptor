"""
gui.py
======
Modern desktop interface for the 3DES File Encryptor (CustomTkinter).

Supports encrypting/decrypting both single files and whole folders.
All cryptography lives in crypto_core.py / key_manager.py.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog

import customtkinter as ctk

import crypto_core
import key_manager

# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ACCENT, ACCENT_HOVER = "#3D7BFC", "#2E6AE6"
CARD_FG  = ("#ffffff", "#1c1f26")
ENTRY_FG = ("#f3f4f6", "#14171d")
BORDER   = ("#e5e7eb", "#2c313b")
MUTED    = ("#6b7280", "#9aa0aa")
TEXT_BTN = ("#374151", "#d1d5db")

OK_FG,   OK_TX   = ("#dcfce7", "#0f3d24"), ("#15803d", "#86efac")
ERR_FG,  ERR_TX  = ("#fee2e2", "#4a1212"), ("#b91c1c", "#fca5a5")
INFO_FG, INFO_TX = ("#dbeafe", "#10243f"), ("#1d4ed8", "#93c5fd")
NEU_FG,  NEU_TX  = ("#f3f4f6", "#181b21"), MUTED


def resource_path(rel: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def human_size(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class EncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("3DES File Encryptor")
        self.geometry("560x690")
        self.minsize(520, 670)
        try:
            self.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass

        self.current_key = None
        self.selected_path = None       # file or folder path
        self.selected_is_dir = False
        self.key_visible = False

        self._build_ui()

    # --------------------------------------------------------------- layout
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        root = ctk.CTkFrame(self, fg_color="transparent")
        root.grid(row=0, column=0, sticky="nsew", padx=22, pady=18)
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(6, weight=1)

        # ---------- header ----------
        header = ctk.CTkFrame(root, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.grid_columnconfigure(0, weight=1)
        titles = ctk.CTkFrame(header, fg_color="transparent")
        titles.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(titles, text="3DES File Encryptor",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(titles,
                     text="Encrypt files & folders  ·  Triple DES + HMAC-SHA256",
                     font=ctk.CTkFont(size=12), text_color=MUTED
                     ).pack(anchor="w", pady=(2, 0))
        self.mode_switch = ctk.CTkSegmentedButton(
            header, values=["Dark", "Light"], width=128,
            command=self._on_mode_change)
        self.mode_switch.set("Dark")
        self.mode_switch.grid(row=0, column=1, sticky="e")

        # ---------- key card ----------
        key_card = self._card(root, 1)
        key_card.grid_columnconfigure(0, weight=1)
        krow = ctk.CTkFrame(key_card, fg_color="transparent")
        krow.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        krow.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(krow, text="Encryption Key",
                     font=ctk.CTkFont(size=15, weight="bold")
                     ).grid(row=0, column=0, sticky="w")
        self.key_pill = ctk.CTkLabel(
            krow, text="\u25CF  No key", corner_radius=11,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=ERR_TX, fg_color=ERR_FG)
        self.key_pill.grid(row=0, column=1, sticky="e", ipadx=10, ipady=3)

        erow = ctk.CTkFrame(key_card, fg_color="transparent")
        erow.grid(row=1, column=0, sticky="ew", padx=16)
        erow.grid_columnconfigure(0, weight=1)
        self.key_var = tk.StringVar()
        self.key_entry = ctk.CTkEntry(
            erow, textvariable=self.key_var, show="\u2022", height=42,
            placeholder_text="Generate or load a key\u2026",
            font=ctk.CTkFont(family="Consolas", size=13))
        self.key_entry.grid(row=0, column=0, sticky="ew")
        self.eye_btn = ctk.CTkButton(
            erow, text="Show", width=64, height=42, command=self._toggle_key,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=MUTED, hover_color=ENTRY_FG)
        self.eye_btn.grid(row=0, column=1, padx=(8, 0))

        brow = ctk.CTkFrame(key_card, fg_color="transparent")
        brow.grid(row=2, column=0, sticky="ew", padx=16, pady=(10, 16))
        for i in range(4):
            brow.grid_columnconfigure(i, weight=1)
        self._btn(brow, "Generate", self.on_generate_key, 0, primary=True)
        self._btn(brow, "Load",     self.on_load_key,     1)
        self._btn(brow, "Save",     self.on_save_key,     2)
        self._btn(brow, "Copy",     self.on_copy_key,     3)

        # ---------- file / folder card ----------
        file_card = self._card(root, 2)
        file_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(file_card, text="File or folder",
                     font=ctk.CTkFont(size=15, weight="bold")
                     ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.drop = ctk.CTkFrame(
            file_card, fg_color=ENTRY_FG, corner_radius=12,
            border_width=2, border_color=BORDER)
        self.drop.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        self.drop.grid_columnconfigure(0, weight=1)
        self.drop_title = ctk.CTkLabel(
            self.drop, text="Nothing selected",
            font=ctk.CTkFont(size=14, weight="bold"))
        self.drop_title.grid(row=0, column=0, padx=16, pady=(18, 2))
        self.drop_sub = ctk.CTkLabel(
            self.drop, text="choose a file or folder below",
            font=ctk.CTkFont(size=12), text_color=MUTED)
        self.drop_sub.grid(row=1, column=0, padx=16, pady=(0, 18))

        choose = ctk.CTkFrame(file_card, fg_color="transparent")
        choose.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 16))
        choose.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(choose, text="Choose file...", height=38,
                      command=self.on_choose_file, fg_color="transparent",
                      border_width=1, border_color=BORDER, text_color=TEXT_BTN,
                      hover_color=ENTRY_FG).grid(row=0, column=0, sticky="ew",
                                                 padx=(0, 5))
        ctk.CTkButton(choose, text="Choose folder...", height=38,
                      command=self.on_choose_folder, fg_color="transparent",
                      border_width=1, border_color=BORDER, text_color=TEXT_BTN,
                      hover_color=ENTRY_FG).grid(row=0, column=1, sticky="ew",
                                                 padx=(5, 0))

        # ---------- actions ----------
        actions = ctk.CTkFrame(root, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", pady=(2, 2))
        actions.grid_columnconfigure((0, 1), weight=1)
        self.encrypt_btn = ctk.CTkButton(
            actions, text="Encrypt", height=50, command=self.on_encrypt,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            font=ctk.CTkFont(size=16, weight="bold"))
        self.encrypt_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.decrypt_btn = ctk.CTkButton(
            actions, text="Decrypt", height=50, command=self.on_decrypt,
            fg_color="transparent", border_width=2, border_color=ACCENT,
            text_color=ACCENT, hover_color=ENTRY_FG,
            font=ctk.CTkFont(size=16, weight="bold"))
        self.decrypt_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        # ---------- progress ----------
        self.progress = ctk.CTkProgressBar(root, mode="indeterminate", height=6)
        self.progress.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.progress.grid_remove()

        # ---------- status ----------
        self.status = ctk.CTkFrame(root, fg_color=NEU_FG, corner_radius=10)
        self.status.grid(row=5, column=0, sticky="ew", pady=(14, 0))
        self.status.grid_columnconfigure(0, weight=1)
        self.status_lbl = ctk.CTkLabel(
            self.status, text="Ready \u2014 generate or load a key to begin.",
            font=ctk.CTkFont(size=13), text_color=NEU_TX,
            anchor="w", justify="left", wraplength=450)
        self.status_lbl.grid(row=0, column=0, sticky="ew", padx=14, pady=11)

    # --------------------------------------------------------- ui factories
    def _card(self, parent, row):
        c = ctk.CTkFrame(parent, fg_color=CARD_FG, corner_radius=14)
        c.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        return c

    def _btn(self, parent, text, cmd, col, primary=False):
        pad = (0 if col == 0 else 5, 0 if col == 3 else 5)
        if primary:
            b = ctk.CTkButton(parent, text=text, height=38, command=cmd,
                              fg_color=ACCENT, hover_color=ACCENT_HOVER,
                              font=ctk.CTkFont(size=13, weight="bold"))
        else:
            b = ctk.CTkButton(parent, text=text, height=38, command=cmd,
                              fg_color="transparent", border_width=1,
                              border_color=BORDER, text_color=TEXT_BTN,
                              hover_color=ENTRY_FG)
        b.grid(row=0, column=col, sticky="ew", padx=pad)
        return b

    # ------------------------------------------------------------- feedback
    def _status(self, text, kind="neutral"):
        palette = {"neutral": (NEU_FG, NEU_TX), "success": (OK_FG, OK_TX),
                   "error": (ERR_FG, ERR_TX), "info": (INFO_FG, INFO_TX)}
        fg, tx = palette[kind]
        self.status.configure(fg_color=fg)
        self.status_lbl.configure(text=text, text_color=tx)
        self.update_idletasks()

    def _set_key_state(self, ok):
        if ok:
            self.key_pill.configure(text="\u25CF  Key ready",
                                    text_color=OK_TX, fg_color=OK_FG)
        else:
            self.key_pill.configure(text="\u25CF  No key",
                                    text_color=ERR_TX, fg_color=ERR_FG)

    def _busy(self, on):
        if on:
            self.progress.grid()
            self.progress.start()
            self.encrypt_btn.configure(state="disabled")
            self.decrypt_btn.configure(state="disabled")
        else:
            self.progress.stop()
            self.progress.grid_remove()
            self.encrypt_btn.configure(state="normal")
            self.decrypt_btn.configure(state="normal")

    # ----------------------------------------------------------- key logic
    def _key_from_entry(self):
        text = self.key_var.get().strip()
        if not text:
            return None
        try:
            return key_manager.b64_to_key(text)
        except Exception:
            return None

    def _require_key(self):
        key = self.current_key or self._key_from_entry()
        if key is None:
            self._status("No valid key. Generate or load a key first.", "error")
            return None
        self.current_key = key
        self._set_key_state(True)
        return key

    def _toggle_key(self):
        self.key_visible = not self.key_visible
        self.key_entry.configure(show="" if self.key_visible else "\u2022")
        self.eye_btn.configure(text="Hide" if self.key_visible else "Show")

    def on_generate_key(self):
        key = key_manager.generate_key()
        self.current_key = key
        self.key_var.set(key_manager.key_to_b64(key))
        self._set_key_state(True)
        self._status("New 24-byte 3DES key generated (Keying Option 1, odd "
                     "parity). Save it so you can decrypt later.", "info")

    def on_save_key(self):
        key = self._require_key()
        if key is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save key", defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")])
        if not path:
            return
        try:
            key_manager.save_key(key, path)
            self._status(f"Key saved \u2192 {os.path.basename(path)}", "success")
        except Exception as e:
            self._status(f"Could not save key: {e}", "error")

    def on_load_key(self):
        path = filedialog.askopenfilename(
            title="Load key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")])
        if not path:
            return
        try:
            key = key_manager.load_key(path)
            self.current_key = key
            self.key_var.set(key_manager.key_to_b64(key))
            self._set_key_state(True)
            self._status(f"Key loaded \u2190 {os.path.basename(path)}", "success")
        except Exception as e:
            self._status(f"Could not load key: {e}", "error")

    def on_copy_key(self):
        key = self._require_key()
        if key is None:
            return
        self.clipboard_clear()
        self.clipboard_append(key_manager.key_to_b64(key))
        self.update()
        self._status("Key copied to clipboard.", "info")

    # -------------------------------------------------- file/folder picking
    def on_choose_file(self):
        path = filedialog.askopenfilename(title="Choose a file")
        if not path:
            return
        self.selected_path = path
        self.selected_is_dir = False
        size = human_size(os.path.getsize(path))
        self.drop_title.configure(text=os.path.basename(path))
        self.drop_sub.configure(text=f"{size}  \u00b7  file")
        self.drop.configure(border_color=ACCENT)
        self._status(f"Selected file: {os.path.basename(path)}  ({size})",
                     "neutral")

    def on_choose_folder(self):
        path = filedialog.askdirectory(title="Choose a folder")
        if not path:
            return
        self.selected_path = path
        self.selected_is_dir = True
        name = os.path.basename(os.path.normpath(path))
        self.drop_title.configure(text=name)
        self.drop_sub.configure(text="folder  \u00b7  zipped, then encrypted")
        self.drop.configure(border_color=ACCENT)
        self._status(f"Selected folder: {name}", "neutral")

    # ------------------------------------------------------------- encrypt
    def on_encrypt(self):
        key = self._require_key()
        if key is None:
            return
        if not self.selected_path:
            self._status("Choose a file or folder first.", "error")
            return

        in_path = self.selected_path
        base = os.path.basename(os.path.normpath(in_path))
        out_path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            initialfile=base + ".enc", defaultextension=".enc")
        if not out_path:
            return

        self._busy(True)
        what = "folder" if self.selected_is_dir else "file"
        self._status(f"Encrypting {what}\u2026", "info")

        def worker():
            try:
                crypto_core.encrypt_path(in_path, out_path, key)
                self.after(0, lambda: self._ok(
                    f"Encryption complete \u2192 {os.path.basename(out_path)}"))
            except crypto_core.CryptoError as e:
                msg = str(e)
                self.after(0, lambda m=msg: self._err(m))
            except Exception as e:
                msg = f"Unexpected error: {e}"
                self.after(0, lambda m=msg: self._err(m))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------- decrypt
    def on_decrypt(self):
        key = self._require_key()
        if key is None:
            return
        if not self.selected_path:
            self._status("Choose the .enc file to decrypt first.", "error")
            return
        if self.selected_is_dir:
            self._status("To decrypt, choose the .enc file (not a folder).",
                         "error")
            return

        in_path = self.selected_path
        self._busy(True)
        self._status("Decrypting\u2026", "info")

        def worker():
            try:
                kind, data = crypto_core.decrypt_blob(in_path, key)
                self.after(0, lambda: self._decrypt_finish(kind, data, in_path))
            except crypto_core.CryptoError as e:
                msg = str(e)
                self.after(0, lambda m=msg: self._err(m))
            except Exception as e:
                msg = f"Unexpected error: {e}"
                self.after(0, lambda m=msg: self._err(m))

        threading.Thread(target=worker, daemon=True).start()

    def _decrypt_finish(self, kind, data, in_path):
        self._busy(False)
        base = os.path.basename(in_path)
        if kind == "folder":
            dest = filedialog.askdirectory(
                title="Choose where to extract the decrypted folder")
            if not dest:
                self._status("Decryption cancelled.", "neutral")
                return
            try:
                crypto_core.extract_zip_bytes(data, dest)
                self._ok(f"Folder restored \u2192 {dest}")
            except Exception as e:
                self._err(f"Could not extract folder: {e}")
        else:
            suggested = (base[:-4] if base.lower().endswith(".enc")
                         else "decrypted_" + base)
            out = filedialog.asksaveasfilename(
                title="Save decrypted file as", initialfile=suggested)
            if not out:
                self._status("Decryption cancelled.", "neutral")
                return
            try:
                with open(out, "wb") as f:
                    f.write(data)
                self._ok(f"File restored \u2192 {os.path.basename(out)}")
            except Exception as e:
                self._err(f"Could not save file: {e}")

    # --------------------------------------------------------- completion
    def _ok(self, msg):
        self._busy(False)
        self._status(msg, "success")

    def _err(self, msg):
        self._busy(False)
        self._status(msg, "error")

    def _on_mode_change(self, value):
        ctk.set_appearance_mode(value.lower())


def main():
    EncryptorApp().mainloop()


if __name__ == "__main__":
    main()
