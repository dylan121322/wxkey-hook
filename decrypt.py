#!/usr/bin/env python3
"""
SQLCipher 4 database decryptor for WeChat 4.x (macOS).

Pure stdlib: AES-CBC via ctypes→CommonCrypto, HMAC via hashlib.
Zero pip dependencies.

Parameters (confirmed for WeChat 4.1):
  page_size = 4096, reserve = 80 (IV16 + HMAC64)
  AES-256-CBC, HMAC-SHA512
  raw-key mode: enc_key IS the AES key (no PBKDF2 derivation)
  mac_key = PBKDF2-HMAC-SHA512(enc_key, salt^0x3a, iter=2, dklen=32)

Usage:
  python3 decrypt.py keys.json /path/to/db_storage /path/to/output/
  python3 decrypt.py keys.json /path/to/db_storage /path/to/output/ --db message/message_4.db
"""

import ctypes
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
from pathlib import Path

# ── CommonCrypto binding ────────────────────────────────────────────
_cc = ctypes.CDLL("/usr/lib/system/libcommonCrypto.dylib")

# CCCryptorStatus CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
#     const void *key, size_t keyLength, const void *iv,   ← iv, NO ivLength
#     const void *dataIn, size_t dataInLength,
#     void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved)
CCCrypt = _cc.CCCrypt
CCCrypt.restype = ctypes.c_int
CCCrypt.argtypes = [
    ctypes.c_uint32,  # op: 0=enc, 1=dec
    ctypes.c_uint32,  # alg: 0=AES
    ctypes.c_uint32,  # options: 0=CBC no-padding
    ctypes.c_void_p,  # key
    ctypes.c_size_t,  # keyLength
    ctypes.c_void_p,  # iv (16 bytes; no separate ivLength arg)
    ctypes.c_void_p,  # dataIn
    ctypes.c_size_t,  # dataInLength
    ctypes.c_void_p,  # dataOut
    ctypes.c_size_t,  # dataOutAvailable
    ctypes.c_void_p,  # dataOutMoved
]

kCCDecrypt = 1
kCCAlgorithmAES = 0
kCCOptionsCBCNoPadding = 0  # SQLCipher pages are block-aligned (4000/4016 % 16 == 0)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-CBC, no padding (SQLCipher page bodies are 16-aligned)."""
    buf = ctypes.create_string_buffer(len(ciphertext) + 16)
    moved = ctypes.c_size_t(0)
    status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionsCBCNoPadding,
        key, len(key),
        iv,                        # iv only — CCCrypt has no ivLength parameter
        ciphertext, len(ciphertext),
        buf, len(buf),
        ctypes.byref(moved),
    )
    if status != 0:
        raise RuntimeError(f"CCCrypt failed with status {status}")
    return buf.raw[: moved.value]


# ── Constants ────────────────────────────────────────────────────────
PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
RESERVE_SIZE = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b"SQLite format 3\x00"

# ── Key derivation ───────────────────────────────────────────────────
def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """Derive HMAC key: PBKDF2-HMAC-SHA512(key, salt^0x3a, 2, 32)."""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SIZE)


def verify_page1_hmac(db_path: str, enc_key: bytes) -> bool:
    """HMAC-verify page 1 of a database — the definitive key check."""
    with open(db_path, "rb") as f:
        page = f.read(PAGE_SIZE)
    if len(page) < PAGE_SIZE:
        return False

    salt = page[:SALT_SIZE]
    mac_key = derive_mac_key(enc_key, salt)

    # HMAC covers: salt(16) → everything up to IV, including the IV
    hmac_input = page[SALT_SIZE : PAGE_SIZE - RESERVE_SIZE + IV_SIZE]
    stored_hmac = page[PAGE_SIZE - HMAC_SIZE : PAGE_SIZE]

    h = hmac_mod.new(mac_key, hmac_input, hashlib.sha512)
    h.update(struct.pack("<I", 1))  # page number, little-endian
    return h.digest() == stored_hmac


# ── Page decrypt ─────────────────────────────────────────────────────
def decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    """Decrypt a single database page. Returns 4096-byte SQLite page."""
    iv = page_data[PAGE_SIZE - RESERVE_SIZE : PAGE_SIZE - RESERVE_SIZE + IV_SIZE]

    if pgno == 1:
        # Page 1: salt(16) + encrypted_body + reserve(80)
        encrypted = page_data[SALT_SIZE : PAGE_SIZE - RESERVE_SIZE]
        decrypted = aes_cbc_decrypt(enc_key, iv, encrypted)
        # Rebuild: SQLite header + decrypted body + zero-filled reserve
        return SQLITE_HDR + decrypted + b"\x00" * RESERVE_SIZE
    else:
        # Other pages: full body(4096-80) + reserve(80)
        encrypted = page_data[: PAGE_SIZE - RESERVE_SIZE]
        decrypted = aes_cbc_decrypt(enc_key, iv, encrypted)
        return decrypted + b"\x00" * RESERVE_SIZE


# ── Full database decrypt ────────────────────────────────────────────
def decrypt_database(db_path: str, out_path: str, enc_key: bytes, quiet: bool = False) -> bool:
    """Decrypt an entire SQLCipher-encrypted database file."""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SIZE
    if file_size % PAGE_SIZE != 0:
        if not quiet:
            print(f"  [WARN] file size {file_size} not multiple of {PAGE_SIZE}")
        total_pages += 1

    # Verify key before touching output
    if not verify_page1_hmac(db_path, enc_key):
        if not quiet:
            print(f"  [ERROR] HMAC verification FAILED — wrong key for {db_path}")
        return False

    if not quiet:
        print(f"  HMAC OK, {total_pages} pages")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SIZE)
            if len(page) < PAGE_SIZE:
                if len(page) == 0:
                    break
                page = page + b"\x00" * (PAGE_SIZE - len(page))

            decrypted = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted)

            if pgno == 1 and decrypted[:16] != SQLITE_HDR:
                if not quiet:
                    print(f"  [WARN] decrypted page1 header mismatch")

            if not quiet and pgno % 10000 == 0:
                pct = 100 * pgno / total_pages
                print(f"  进度: {pgno}/{total_pages} ({pct:.1f}%)")

    return True


# ── Batch decrypt ────────────────────────────────────────────────────
def decrypt_all(keys: dict, db_dir: str, out_dir: str, quiet: bool = False) -> tuple[int, int]:
    """Decrypt all databases in keys dict. Returns (success, failed)."""
    success, failed = 0, 0

    for rel_path, info in sorted(keys.items()):
        enc_key_hex = info.get("enc_key", "")
        if not enc_key_hex:
            if not quiet:
                print(f"SKIP: {rel_path} (no key)")
            failed += 1
            continue

        src = os.path.join(db_dir, rel_path)
        dst = os.path.join(out_dir, rel_path)
        sz_mb = os.path.getsize(src) / (1024 * 1024) if os.path.exists(src) else 0

        if not quiet:
            print(f"解密: {rel_path} ({sz_mb:.1f}MB) ...", end=" ")

        enc_key = bytes.fromhex(enc_key_hex)
        if decrypt_database(src, dst, enc_key, quiet=quiet):
            # Quick sqlite3 validation
            try:
                import sqlite3
                conn = sqlite3.connect(dst)
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                conn.close()
                if not quiet:
                    print(f"OK! 表: {len(tables)}")
                success += 1
            except Exception as e:
                if not quiet:
                    print(f"sqlite3 check failed: {e}")
                failed += 1
        else:
            if not quiet:
                print("FAILED")
            failed += 1

        # Clean up stray WAL/SHM from sqlite3.connect
        for suffix in ("-shm", "-wal"):
            residual = dst + suffix
            if os.path.exists(residual):
                try:
                    os.remove(residual)
                except OSError:
                    pass

    return success, failed


# ── CLI ──────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 4:
        print(__doc__)
        print("Usage: python3 decrypt.py <keys.json> <db_dir> <out_dir> [--db <rel_path>]")
        sys.exit(1)

    keys_file, db_dir, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(keys_file) as f:
        keys = json.load(f)

    # Optional: single DB mode
    single_db = None
    if "--db" in sys.argv:
        idx = sys.argv.index("--db")
        if idx + 1 < len(sys.argv):
            single_db = sys.argv[idx + 1]
            keys = {single_db: keys[single_db]} if single_db in keys else {}

    if not keys:
        print("[!] No keys to decrypt.")
        sys.exit(1)

    print(f"Keys: {len(keys)}, Out: {out_dir}\n")
    ok, fail = decrypt_all(keys, db_dir, out_dir)
    print(f"\nDone: {ok} success, {fail} failed")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
