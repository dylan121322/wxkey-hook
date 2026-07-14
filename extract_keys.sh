#!/bin/bash
# extract_keys.sh — One-shot: capture WeChat SQLCipher keys via lldb + CommonCrypto hooks.
#
# Workflow:
#   1. Verify preconditions: resigned WeChat exists, sudo available.
#   2. Capture stage: lldb --waitfor, attach at _dyld_start before any DB opens.
#   3. Hook CCCryptorCreate + CCKeyDerivationPBKDF → captured_keys.txt.
#   4. Prompt user: quit WeChat, then re-launch resigned copy.
#   5. Wait for WeChat to finish opening databases (key capture completes).
#   6. Stop lldb, run match_keys.py → keys.json.
#
# Output: keys.json (format: {"rel_path": {"enc_key": "hex64"}})
#
# Usage:
#   bash extract_keys.sh [db_dir] [output_keys.json]
#     db_dir   — path to db_storage (auto-detected if omitted)
#     output   — path for keys.json (default: ./keys.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTURED_FILE="/tmp/wxkey_captured.txt"
HOOK_PY="$SCRIPT_DIR/hook_keys.py"
RESIGNED_APP="$HOME/WeChat-resign.app"
DB_DIR="${1:-auto}"
OUTPUT="${2:-$SCRIPT_DIR/keys.json}"

echo "=========================================="
echo "  wxkey-hook: WeChat Key Extractor"
echo "=========================================="
echo

# ── Preflight ───────────────────────────────────────────────────────
if [ ! -f "$HOOK_PY" ]; then
    echo "[ERROR] hook_keys.py not found at $HOOK_PY"
    exit 1
fi

if [ ! -d "$RESIGNED_APP" ]; then
    echo "[ERROR] Resigned WeChat not found at $RESIGNED_APP"
    echo "  Run: bash $SCRIPT_DIR/resign_wechat.sh"
    exit 1
fi

# Auto-detect db_dir
if [ "$DB_DIR" = "auto" ]; then
    BASE="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    if [ ! -d "$BASE" ]; then
        echo "[ERROR] Cannot auto-detect db_dir (base not found: $BASE)"
        echo "  Usage: bash $0 /path/to/db_storage"
        exit 1
    fi
    # Pick the most recently modified db_storage
    DB_DIR=$(find "$BASE" -maxdepth 3 -name "db_storage" -type d \
        -exec stat -f "%m %N" {} \; 2>/dev/null \
        | sort -rn | head -1 | cut -d' ' -f2-)
    if [ -z "$DB_DIR" ]; then
        echo "[ERROR] No db_storage found under $BASE"
        exit 1
    fi
    echo "[auto] db_dir = $DB_DIR"
fi

if [ ! -d "$DB_DIR" ]; then
    echo "[ERROR] db_dir not found: $DB_DIR"
    exit 1
fi

# ── Capture stage ───────────────────────────────────────────────────
echo
echo "--- Capture Stage ---"
echo

# Clean previous capture. The hook (run by sudo lldb) writes as root, so create
# the file as root and make it world-readable — the match stage reads it as $USER.
sudo bash -c ": > '$CAPTURED_FILE' && chmod 644 '$CAPTURED_FILE'"

# Build lldb command file
LLDB_CMDS="/tmp/wxkey_lldb.cmds"
cat > "$LLDB_CMDS" <<LLDBEOF
command script import $HOOK_PY
break set -n CCCryptorCreate
break command add -F hook_keys.cryptor_bp
break set -n CCKeyDerivationPBKDF
break command add -F hook_keys.pbkdf_bp
break set -n CCHmacInit
break command add -F hook_keys.hmac_bp
continue
LLDBEOF

echo "[*] Starting lldb in wait-for mode..."
echo "    lldb will attach to WeChat at process creation (_dyld_start)."
echo

# Kill any running WeChat first (so --waitfor catches the fresh launch)
killall WeChat 2>/dev/null || true
sleep 2

echo
echo "+----------------------------------------------------------+"
echo "|  lldb is about to wait for WeChat to start.              |"
echo "|                                                          |"
echo "|  ACTION: after lldb prints 'Waiting to attach', launch   |"
echo "|          the RESIGNED WeChat in another terminal / Finder:|"
echo "|    open $HOME/WeChat-resign.app"
echo "|                                                          |"
echo "|  Keys stream below as databases open. When WeChat is     |"
echo "|  fully loaded (no new keys for a few seconds), press     |"
echo "|  Ctrl-C ONCE to stop capture and continue to matching.   |"
echo "+----------------------------------------------------------+"
echo

# Run lldb in the FOREGROUND. Ctrl-C (SIGINT) stops lldb; we trap it so the
# script proceeds to the matching stage instead of aborting.
# --waitfor attaches at _dyld_start; breakpoints resolve once libcommonCrypto loads.
trap 'echo; echo "[*] Capture stopped by user."' INT
set +e
sudo lldb -b \
    -o "process attach --name WeChat --waitfor" \
    -s "$LLDB_CMDS" \
    2>&1 | tee /tmp/wxkey_lldb.log
set -e
trap - INT

echo
echo "--- Matching Stage ---"

# ── Match stage ─────────────────────────────────────────────────────
if [ ! -s "$CAPTURED_FILE" ]; then
    echo "[ERROR] No keys captured! captured file is empty: $CAPTURED_FILE"
    echo "  Check:"
    echo "    1. Did you launch the resigned WeChat ($RESIGNED_APP)?"
    echo "    2. Does the resigned copy have get-task-allow? (run resign_wechat.sh)"
    echo "    3. Did WeChat finish opening databases?"
    exit 1
fi

echo "[*] Matching keys to databases..."
python3 "$SCRIPT_DIR/match_keys.py" "$CAPTURED_FILE" "$DB_DIR" "$OUTPUT"

echo
echo "=========================================="
echo "  Done."
echo "  Keys saved to: $OUTPUT"
echo "  Captured data: $CAPTURED_FILE"
echo "=========================================="
