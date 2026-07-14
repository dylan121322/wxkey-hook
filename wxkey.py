#!/usr/bin/env python3
"""
wxkey — WeChat 4.x SQLCipher key extraction + decryption tool (macOS).

Zero pip dependencies. Uses system lldb for hooking, CommonCrypto via ctypes for
decryption.

Commands:
  resign      Ad-hoc re-sign WeChat.app for debugging access.
  extract     Capture encryption keys via lldb CommonCrypto hooks.
  decrypt     Decrypt databases using keys.json.
  verify      Verify a single database key via HMAC self-check.
  all         resign + extract + decrypt in sequence.

Auto-detection:
  db_dir is auto-detected from ~/Library/Containers/com.tencent.xinWeChat/...
  If multiple wxids are found, the most recently modified is chosen.
  Override with --db-dir or WXKEY_DB_DIR environment variable.

Usage:
  python3 wxkey.py resign
  python3 wxkey.py extract [--db-dir /path/to/db_storage]
  python3 wxkey.py decrypt [--out decrypted/]
  python3 wxkey.py verify /path/to/message_4.db <key_hex>
  python3 wxkey.py all
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
KEYS_FILE = SCRIPT_DIR / "keys.json"
DEFAULT_OUT = SCRIPT_DIR / "decrypted"
RESIGN_SH = SCRIPT_DIR / "resign_wechat.sh"
EXTRACT_SH = SCRIPT_DIR / "extract_keys.sh"


# ── Helpers ──────────────────────────────────────────────────────────
def _auto_db_dir() -> str:
    """Auto-detect the most recently modified db_storage directory."""
    env = os.environ.get("WXKEY_DB_DIR", "")
    if env and os.path.isdir(env):
        return env

    base = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    )
    if not os.path.isdir(base):
        raise FileNotFoundError(f"Base directory not found: {base}")

    candidates = []
    for root, dirs, files in os.walk(base):
        if "db_storage" in dirs:
            path = os.path.join(root, "db_storage")
            try:
                mtime = os.path.getmtime(os.path.join(path, "message"))
            except OSError:
                mtime = os.path.getmtime(path)
            candidates.append((mtime, path))
        # Only go 3 levels deep
        depth = root[len(base) :].count(os.sep)
        if depth >= 3:
            dirs.clear()

    if not candidates:
        raise FileNotFoundError(f"No db_storage found under {base}")

    candidates.sort(reverse=True)
    path = candidates[0][1]
    print(f"[auto] db_dir = {path}")
    return path


def _run(cmd: list[str], **kwargs) -> int:
    """Run a command, streaming output."""
    return subprocess.run(cmd, **kwargs).returncode


# ── Commands ─────────────────────────────────────────────────────────
def cmd_resign(args):
    """Ad-hoc re-sign WeChat for debugging."""
    return _run(["bash", str(RESIGN_SH)])


def cmd_extract(args):
    """Capture keys via lldb CommonCrypto hooks."""
    db_dir = args.db_dir or _auto_db_dir()
    output = args.output or str(KEYS_FILE)
    return _run(["bash", str(EXTRACT_SH), db_dir, output])


def cmd_decrypt(args):
    """Decrypt databases using keys.json."""
    from decrypt import decrypt_all

    keys_file = args.keys_file or str(KEYS_FILE)
    db_dir = args.db_dir or _auto_db_dir()
    out_dir = args.out_dir or str(DEFAULT_OUT)

    if not os.path.exists(keys_file):
        print(f"[!] Keys file not found: {keys_file}")
        print("    Run: python3 wxkey.py extract")
        return 1

    with open(keys_file) as f:
        keys = json.load(f)

    print(f"Keys: {len(keys)}, db_dir: {db_dir}, out: {out_dir}\n")
    ok, fail = decrypt_all(keys, db_dir, out_dir)
    print(f"\nDone: {ok} success, {fail} failed")
    return 1 if fail else 0


def cmd_verify(args):
    """HMAC-verify a single key against a database."""
    from decrypt import verify_page1_hmac

    db_path = args.db_path
    key_hex = args.key_hex

    if not os.path.exists(db_path):
        print(f"[!] Database not found: {db_path}")
        return 1

    try:
        enc_key = bytes.fromhex(key_hex)
    except ValueError:
        print(f"[!] Invalid key hex: {key_hex}")
        return 1

    ok = verify_page1_hmac(db_path, enc_key)
    if ok:
        print(f"✓ HMAC verified: {db_path}")
        return 0
    else:
        print(f"✗ HMAC FAILED: {db_path} — wrong key?")
        return 1


def cmd_all(args):
    """resign + extract + decrypt in sequence."""
    print("=" * 50)
    print("  wxkey: resign → extract → decrypt")
    print("=" * 50)
    print()

    # Step 1: resign
    print("── Step 1/3: Resign ──")
    rc = cmd_resign(args)
    if rc != 0:
        print("[!] Resign failed. Continuing anyway (may already be resigned)...")

    # Step 2: extract
    print("\n── Step 2/3: Extract keys ──")
    rc = cmd_extract(args)
    if rc != 0:
        print("[!] Key extraction failed.")
        return rc

    # Step 3: decrypt
    print("\n── Step 3/3: Decrypt ──")
    return cmd_decrypt(args)


# ── Main ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="wxkey",
        description="WeChat 4.x SQLCipher key extraction + decryption (macOS)",
    )
    sub = parser.add_subparsers(dest="command", title="commands")

    # resign
    p = sub.add_parser("resign", help="Ad-hoc re-sign WeChat for debugging")

    # extract
    p = sub.add_parser("extract", help="Capture keys via lldb CommonCrypto hooks")
    p.add_argument("--db-dir", help="Path to db_storage (auto-detected if omitted)")
    p.add_argument("-o", "--output", help="Output keys.json path")

    # decrypt
    p = sub.add_parser("decrypt", help="Decrypt databases")
    p.add_argument("--keys-file", help="Path to keys.json")
    p.add_argument("--db-dir", help="Path to db_storage")
    p.add_argument("--out-dir", help="Output directory for decrypted databases")

    # verify
    p = sub.add_parser("verify", help="Verify a single key")
    p.add_argument("db_path", help="Path to encrypted database")
    p.add_argument("key_hex", help="64-char hex key")

    # all
    _ = sub.add_parser("all", help="Resign + extract + decrypt")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "resign": cmd_resign,
        "extract": cmd_extract,
        "decrypt": cmd_decrypt,
        "verify": cmd_verify,
        "all": cmd_all,
    }

    rc = commands[args.command](args)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
