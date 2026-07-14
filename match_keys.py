#!/usr/bin/env python3
"""
Match captured CommonCrypto keys to database files via salt XOR 0x3a.

Mechanism:
  1. Parse captured_keys.txt — extract rounds=2 PBKDF (rawkey+salt) and AESKEY lines.
  2. Walk db_dir, read file_salt (first 16 bytes) from each .db.
  3. Match: file_salt directly, or file_salt XOR 0x3a → matches PBKDF salt.
  4. For each match, HMAC-verify page 1 (calls decrypt.verify_page1_hmac).
  5. Output keys.json: {"rel/path": {"enc_key": "hex..."}}.

Usage:
  python3 match_keys.py <captured_keys.txt> <db_dir> <output_keys.json>
"""

import json
import os
import re
import sys
from pathlib import Path

# Reuse HMAC verification from decrypt.py (same project, not old wechat-decrypt)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decrypt import verify_page1_hmac


def xor_3a(hex_salt: str) -> str:
    """XOR each byte of hex string with 0x3A."""
    return bytes(b ^ 0x3A for b in bytes.fromhex(hex_salt)).hex()


def parse_captured(path: str) -> dict[str, set[str]]:
    """Parse captured_keys.txt → {rawkey_hex: set of salt_hex} (rounds=2 only)."""
    raw2salts: dict[str, set[str]] = {}
    pbkdf_re = re.compile(
        r"rounds=(\d+)\s+pwlen=(\d+)\s+rawkey=([0-9a-f]{64})\s+salt=([0-9a-f]{32})"
    )

    with open(path, errors="ignore") as f:
        for line in f:
            m = pbkdf_re.search(line)
            if not m:
                continue
            rounds = int(m.group(1))
            if rounds != 2:
                continue  # only per-DB derivations, not master key
            rawkey = m.group(3)
            salt = m.group(4)
            raw2salts.setdefault(rawkey, set()).add(salt)

    return raw2salts


def collect_dbs(db_dir: str) -> list[str]:
    """Recursively find all .db files under db_dir."""
    dbs = []
    for root, dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith("-wal") and not f.endswith("-shm"):
                dbs.append(os.path.join(root, f))
    return sorted(dbs)


def read_file_salt(db_path: str) -> str | None:
    """Read first 16 bytes of a .db file. Returns hex string or None."""
    try:
        with open(db_path, "rb") as f:
            return f.read(16).hex()
    except OSError:
        return None


def match_keys(captured_file: str, db_dir: str, output_file: str) -> dict:
    """
    Match captured keys to databases. Returns {rel_path: {"enc_key": hex}}.
    Only includes keys that pass HMAC self-verification.
    """
    raw2salts = parse_captured(captured_file)
    if not raw2salts:
        print("[!] No rounds=2 PBKDF entries found in captured file.")
        print("    Make sure hook_keys.py captured CCKeyDerivationPBKDF calls.")
        return {}

    print(f"Parsed {len(raw2salts)} raw keys from captured file.")

    # Build reverse index: salt → rawkey
    salt2raw: dict[str, str] = {}
    for rawkey, salts in raw2salts.items():
        for s in salts:
            salt2raw[s] = rawkey

    dbs = collect_dbs(db_dir)
    print(f"Found {len(dbs)} database files.")

    matched: dict[str, dict[str, str]] = {}
    verified, failed_hmac, unmatched = 0, 0, 0

    for db_path in dbs:
        rel = os.path.relpath(db_path, db_dir)
        file_salt = read_file_salt(db_path)
        if not file_salt:
            print(f"  ✗ {rel:50s} cannot read salt")
            unmatched += 1
            continue

        # Try direct match, then XOR 0x3A match
        enc_key_hex = None
        how = None

        if file_salt in salt2raw:
            enc_key_hex = salt2raw[file_salt]
            how = "direct"
        else:
            mac_salt = xor_3a(file_salt)
            if mac_salt in salt2raw:
                enc_key_hex = salt2raw[mac_salt]
                how = "XOR 0x3A"

        if not enc_key_hex:
            print(f"  ✗ {rel:50s} salt={file_salt} unmatched")
            unmatched += 1
            continue

        # HMAC self-verification
        enc_key = bytes.fromhex(enc_key_hex)
        if verify_page1_hmac(db_path, enc_key):
            matched[rel] = {"enc_key": enc_key_hex}
            print(f"  ✓ {rel:50s} {how:>8}  HMAC OK")
            verified += 1
        else:
            print(f"  ✗ {rel:50s} {how:>8}  HMAC FAIL — key rejected")
            failed_hmac += 1

    # Write output
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(matched, f, indent=2, ensure_ascii=False)

    print(f"\nResults: {verified} matched & verified, "
          f"{failed_hmac} HMAC-failed, {unmatched} unmatched "
          f"— wrote {output_file}")

    return matched


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        print("Usage: python3 match_keys.py <captured.txt> <db_dir> <keys.json>")
        sys.exit(1)

    captured_file, db_dir, output_file = sys.argv[1], sys.argv[2], sys.argv[3]

    if not os.path.exists(captured_file):
        print(f"[!] Captured file not found: {captured_file}")
        sys.exit(1)
    if not os.path.isdir(db_dir):
        print(f"[!] db_dir not found: {db_dir}")
        sys.exit(1)

    result = match_keys(captured_file, db_dir, output_file)
    if not result:
        print("\n[!] No keys matched. Possible causes:")
        print("    1. captured_keys.txt is empty — did lldb hook fire?")
        print("    2. db_dir is wrong — check path")
        print("    3. WeChat uses a different salt scheme (not XOR 0x3A)")
        sys.exit(1)


if __name__ == "__main__":
    main()
