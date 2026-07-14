#!/bin/bash
# resign_wechat.sh — Ad-hoc re-sign WeChat.app to allow task_for_pid debugging.
#
# Why: WeChat ships with hardened runtime (flags=0x10000), which blocks
# mach_vm_read / task_for_pid. We copy it to $HOME (bypassing macOS Sequoia's
# com.apple.provenance xattr on /Applications), strip code signatures, and
# re-sign with get-task-allow entitlement.
#
# Result: $HOME/WeChat-resign.app — debuggable, lldb-attachable.
#
# Run this ONCE. The resigned copy persists across reboots.
# It auto-detects whether the source is /Applications/WeChat.app or an
# already-resigned copy in $HOME.

set -euo pipefail

SRC="${WE_CHAT_SRC:-/Applications/WeChat.app}"
DST="$HOME/WeChat-resign.app"
ENTITLEMENTS="$(cd "$(dirname "$0")" && pwd)/debug.entitlements"

echo "=== WeChat ad-hoc resign tool ==="
echo "Source: $SRC"
echo "Output: $DST"
echo

# ── Verify source exists ──────────────────────────────────────────
if [ ! -d "$SRC" ]; then
    echo "[ERROR] WeChat.app not found at $SRC"
    echo "  Set WE_CHAT_SRC to your WeChat.app path, e.g.:"
    echo "  WE_CHAT_SRC=/Applications/WeChat.app bash $0"
    exit 1
fi

# ── Generate entitlements if missing ───────────────────────────────
if [ ! -f "$ENTITLEMENTS" ]; then
    cat > "$ENTITLEMENTS" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
PLIST
    echo "[+] Created $ENTITLEMENTS"
fi

# ── Copy WeChat (preserve no extended attrs) ────────────────────────
echo "[1/3] Copying WeChat.app (preserving no xattrs)..."
if [ -d "$DST" ]; then
    echo "      Removing old copy..."
    rm -rf "$DST"
fi
ditto --noextattr --noqtn "$SRC" "$DST"
echo "      Done."

# ── Strip all code signatures ──────────────────────────────────────
echo "[2/3] Stripping code signatures..."
# Remove signature from main binary and all nested bundles
codesign --remove-signature "$DST" 2>/dev/null || true
find "$DST/Contents" -type f -perm +111 2>/dev/null | while read -r f; do
    if file -b "$f" | grep -q "Mach-O"; then
        codesign --remove-signature "$f" 2>/dev/null || true
    fi
done
# Remove signature from all nested .app bundles
find "$DST" -name "*.app" -type d | while read -r app; do
    codesign --remove-signature "$app" 2>/dev/null || true
done
echo "      Done."

# ── Ad-hoc re-sign with get-task-allow ──────────────────────────────
echo "[3/3] Ad-hoc signing with debug entitlements..."
# Clear xattrs first (Sequoia provenance blocks re-signing otherwise)
xattr -rc "$DST" 2>/dev/null || true
# NOTE: deliberately NO "--options runtime". Hardened runtime blocks
# task_for_pid even with get-task-allow; we must strip it, not re-add it.
codesign --force --deep --sign - \
    --entitlements "$ENTITLEMENTS" \
    "$DST"
echo "      Done."

echo
echo "=== Ready ==="
echo "Debug-capable WeChat at: $DST"
echo
echo "Usage:"
echo "  sudo $DST/Contents/MacOS/WeChat &    # launch manually"
echo "  open $DST                            # or via Finder"
echo
echo "To revert: rm -rf $DST"
