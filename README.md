# wxkey-hook

**WeChat 4.x macOS database key extraction + decryption tool**

[中文文档](README.zh-CN.md) · Zero pip dependencies · Pure Python stdlib + macOS `libcommonCrypto`

> ⚠️ **For research and personal data recovery only.** Use exclusively on your own
> device and your own WeChat account. See [Legal](#legal).

## Why this exists

On WeChat 4.1 (macOS), the 32-byte per-database SQLCipher key **is no longer
resident in process memory as plaintext** — an 8.3 GB memory scan of a running
WeChat, searching for 21 known-correct keys, produced **zero hits**. Every
memory-scanning tool (the previous generation of `find_all_keys_macos`, and most
community forks) breaks on 4.1 for this reason.

The key only appears — in a CPU register — at the instant WeChat calls Apple's
CommonCrypto to open a database. This tool sets an lldb breakpoint on
`CCCryptorCreate` (a **system-library** symbol that is **not stripped**), reads
the AES key from the ARM64 `x3` register, and attaches with `--waitfor` so the
breakpoint is armed before any database opens — capturing every key in one launch.

See [MECHANISM.md](MECHANISM.md) for the full reverse-engineering write-up.

## Requirements

- **macOS** (verified on Apple Silicon; Intel should work but is untested)
- **Xcode Command Line Tools** (provides `lldb`) — `xcode-select --install`
- **Python 3.10+** (stdlib only — no `pip install`)
- **sudo** (`task_for_pid` requires root to read another process's memory)

### Dependency declaration

| Dependency | Source | License |
|------------|--------|---------|
| Python `hashlib`, `hmac`, `ctypes`, `json`, `sqlite3` | Python stdlib | PSF |
| `libcommonCrypto.dylib` | macOS system library | APSL |
| `lldb` | Xcode CLT (LLVM) | Apache-2.0 with LLVM exception |

**No pip / brew / npm packages.** Nothing to install beyond the system tools above.

## Quick start

### 1. Re-sign WeChat (once)

```bash
bash resign_wechat.sh
```

WeChat ships with a hardened runtime that blocks debuggers. This copies it to
`~/WeChat-resign.app` and ad-hoc re-signs it with the `get-task-allow`
entitlement. The copy persists across reboots.

### 2. Extract keys

```bash
python3 wxkey.py extract
```

This will:
1. Kill any running WeChat.
2. Launch `lldb` in `--waitfor` mode (attaches at `_dyld_start`).
3. Prompt you to launch `~/WeChat-resign.app`.
4. Capture keys as WeChat opens its databases.
5. Match each key to its `.db` file and write `keys.json`.

Press `Ctrl-C` once when WeChat has finished loading (no new keys appear).

### 3. Decrypt

```bash
python3 wxkey.py decrypt
```

Decrypted databases land in `./decrypted/` — open them with any SQLite tool.

### One-shot

```bash
python3 wxkey.py all      # resign + extract + decrypt
```

## Commands

| Command | Description |
|---------|-------------|
| `wxkey.py resign` | Ad-hoc re-sign WeChat for debugging |
| `wxkey.py extract` | Capture keys → `keys.json` |
| `wxkey.py decrypt` | Decrypt all databases → `decrypted/` |
| `wxkey.py verify <db> <key>` | HMAC-verify a single database key |
| `wxkey.py all` | resign + extract + decrypt |

## How it works (one paragraph)

WeChat 4.x encrypts each database with SQLCipher 4 (AES-256-CBC, HMAC-SHA512,
4096-byte pages, 80-byte reserve). It uses **raw-key mode**: the 32-byte key is
the AES key directly, with no PBKDF2 stretching. All crypto routes through Apple
CommonCrypto, not BoringSSL — which is why hooks on `PKCS5_PBKDF2_HMAC` or
`AES_set_decrypt_key` never fire. We hook `CCCryptorCreate` instead, grab the
key, then match it to a file by XOR-ing the file's salt with `0x3A` (SQLCipher's
MAC-salt transform) and comparing against the salt seen in `CCKeyDerivationPBKDF`.
Every matched key is HMAC-verified against page 1 before it is trusted.

## Security notes

- `keys.json` contains **plaintext database keys**. Keep it private; it is in
  `.gitignore`. Consider `chmod 600 keys.json`.
- This tool runs **entirely locally**. It makes no network connections.
- It only **reads** WeChat's process memory and database files — it never
  modifies WeChat's data.

## Legal

This project is intended for **security research, education, and recovery of your
own data**. Extracting keys requires root, physical access, and re-signing —
i.e. it only works on a machine and account you already control.

Do not use it against accounts or devices you do not own. You are responsible for
complying with WeChat's Terms of Service and the laws of your jurisdiction.

## License

[MIT](LICENSE)
