"""
lldb Python breakpoint script: hook Apple CommonCrypto to capture
WeChat 4.x SQLCipher encryption keys at database-open time.

Hook points (all in libcommonCrypto.dylib — system library, symbols NOT stripped):

  CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef)
    arm64: x0=op  x1=alg  x2=options  x3=key(→AES key)  x4=keyLength  x5=iv

  CCKeyDerivationPBKDF(alg, password, passwordLen, salt, saltLen, prf, rnd, dk, dkLen)
    arm64: x0=alg  x1=password(→raw key)  x2=passwordLen  x3=salt  x4=saltLen
           x5=prf  x6=rounds  x7=derivedKey

  CCHmacInit(ctx, algorithm, key, keyLength)
    arm64: x0=ctx  x1=algorithm  x2=key(→mac key)  x3=keyLength

Mechanism (discovered 2026-07-14):
  - WeChat 4.1 uses raw-key SQLCipher mode: AES key == raw key (no PBKDF2).
  - key is NOT resident in memory in plaintext (confirmed: 8361MB scan → 0 hits).
  - key appears ONLY in registers/stack during CCCryptorCreate calls at DB open.
  - This is why every prior "scan memory for 32-byte key" approach fails on 4.1.
  - salt XOR 0x3a matching: file_salt ^ 0x3a = salt seen in CCKeyDerivationPBKDF
    rounds=2 calls → links rawkey to database file.

Usage (loaded by lldb):
  (lldb) command script import hook_keys.py
  (lldb) break set -n CCCryptorCreate
  (lldb) break command add -F hook_keys.cryptor_bp
  (lldb) break set -n CCKeyDerivationPBKDF
  (lldb) break command add -F hook_keys.pbkdf_bp
  (lldb) continue
"""

import lldb

OUT = "/tmp/wxkey_captured.txt"

_seen = set()


def _read_mem(proc, ptr: int, length: int) -> str | None:
    """Read `length` bytes from process memory at `ptr`. Returns hex string or None."""
    if ptr == 0 or length <= 0 or length > 256:
        return None
    err = lldb.SBError()
    data = proc.ReadMemory(ptr, length, err)
    return data.hex() if err.Success() else None


def _log(tag: str, fields: list[tuple[str, object]]):
    """Deduplicated log to stdout + append to OUT file."""
    line = f"[{tag}] " + " ".join(f"{k}={v}" for k, v in fields)
    if line in _seen:
        return
    _seen.add(line)
    with open(OUT, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


# ── Breakpoint callbacks ─────────────────────────────────────────────

def cryptor_bp(frame, bp_loc, internal_dict):
    """CCCryptorCreate — capture the AES key.

    AES key length is always 16, 24, or 32 bytes. WeChat uses 32.
    """
    proc = frame.GetThread().GetProcess()
    key_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
    key_len = frame.FindRegister("x4").GetValueAsUnsigned()

    if key_ptr == 0 or key_len not in (16, 24, 32):
        return False  # don't stop

    key_hex = _read_mem(proc, key_ptr, int(key_len))
    if key_hex:
        _log("AESKEY", [("len", key_len), ("key", key_hex)])

    return False  # never stop the process


def pbkdf_bp(frame, bp_loc, internal_dict):
    """CCKeyDerivationPBKDF — capture the raw key + salt for DB matching.

    rounds=2: per-database raw key → mac_key derivation.
    rounds=256000: master key → per-database key derivation (WeChat internal).
    We want rounds=2 for salt matching.
    """
    proc = frame.GetThread().GetProcess()
    pwd_ptr = frame.FindRegister("x1").GetValueAsUnsigned()
    pwd_len = frame.FindRegister("x2").GetValueAsUnsigned()
    salt_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
    salt_len = frame.FindRegister("x4").GetValueAsUnsigned()
    rounds = frame.FindRegister("x6").GetValueAsUnsigned()

    if pwd_ptr == 0 or pwd_len == 0 or pwd_len > 64:
        return False

    pwd_hex = _read_mem(proc, pwd_ptr, int(pwd_len))
    salt_hex = _read_mem(proc, salt_ptr, int(salt_len)) if 0 < salt_len <= 32 else None

    if pwd_hex:
        _log("PBKDF", [
            ("rounds", rounds),
            ("pwlen", pwd_len),
            ("rawkey", pwd_hex),
            ("salt", salt_hex or "?"),
        ])

    return False


def hmac_bp(frame, bp_loc, internal_dict):
    """CCHmacInit — capture the MAC key (32 bytes from PBKDF2)."""
    proc = frame.GetThread().GetProcess()
    key_ptr = frame.FindRegister("x2").GetValueAsUnsigned()
    key_len = frame.FindRegister("x3").GetValueAsUnsigned()

    if key_ptr == 0 or key_len == 0 or key_len > 64:
        return False

    key_hex = _read_mem(proc, key_ptr, int(key_len))
    if key_hex and key_len in (16, 24, 32):
        _log("MACKEY", [("len", key_len), ("key", key_hex)])

    return False


def __lldb_init_module(debugger, internal_dict):
    """Called by lldb when the script is imported. Set breakpoints here."""
    pass  # breakpoints are set by the caller (extract_keys.sh)
