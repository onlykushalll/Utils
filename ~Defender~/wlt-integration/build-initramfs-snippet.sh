#!/usr/bin/env bash
# Phase 3.2: build-initramfs-snippet.sh — sourced by WLTIOS/scripts/build-initramfs64.sh
#
# Bundles Guardian binaries + config + BPF + signatures + ML model into the
# 64-bit initramfs. All binaries must be statically linked (built with
# DAEMON_LDFLAGS="-static ...").
#
# Usage (from build-initramfs64.sh):
#   source /path/to/guardian/wlt-integration/build-initramfs-snippet.sh
#
# Expects:
#   $INITRAMFS_DIR — the staging root directory (set by build-initramfs64.sh)
#   $GUARDIAN_SRC  — path to the guardian source tree (default: ../guardian)

set -e

GUARDIAN_SRC="${GUARDIAN_SRC:-$(pwd)/../guardian}"
INITRAMFS_DIR="${INITRAMFS_DIR:-$(pwd)/initramfs64}"

if [ ! -d "$GUARDIAN_SRC" ]; then
    echo "[guardian-bundle] source not found: $GUARDIAN_SRC" >&2
    exit 1
fi

# Target layout in initramfs
G_DST="$INITRAMFS_DIR/etc/wlt/guardian"
G_BIN="$INITRAMFS_DIR/usr/sbin"
mkdir -p "$G_DST" "$G_BIN" "$G_DST/bpf" "$G_DST/baseline"

echo "[guardian-bundle] copying binaries (must be static-linked)..."
# Binaries -> /usr/sbin with wlt- prefix
cp -f "$GUARDIAN_SRC/build/guardian"            "$G_BIN/wlt-guardian"
cp -f "$GUARDIAN_SRC/build/guardian_watchdog"   "$G_BIN/wlt-guardian-watchdog"
cp -f "$GUARDIAN_SRC/build/mcp_server"          "$G_BIN/wlt-mcp-server"
cp -f "$GUARDIAN_SRC/build/kairos"              "$G_BIN/wlt-kairos" 2>/dev/null || true
chmod 0755 "$G_BIN/wlt-guardian" "$G_BIN/wlt-guardian-watchdog" "$G_BIN/wlt-mcp-server"

echo "[guardian-bundle] copying BPF program..."
cp -f "$GUARDIAN_SRC/build/bpf/guardian.bpf.o"  "$G_DST/guardian.bpf.o"

echo "[guardian-bundle] copying signatures + rules..."
cp -f "$GUARDIAN_SRC/signatures/guardian.yarc"  "$G_DST/guardian.yarc"
cp -f "$GUARDIAN_SRC/rules/guardian.policy"     "$G_DST/guardian.policy"
cp -f "$GUARDIAN_SRC/rules/ebpf.rules"          "$G_DST/ebpf.rules"
cp -f "$GUARDIAN_SRC/rules/guardian.yar"        "$G_DST/guardian.yar"
cp -f "$GUARDIAN_SRC/update_pubkey.pem"         "$G_DST/update_pubkey.pem"

echo "[guardian-bundle] copying FIM baseline + ML model..."
cp -f "$GUARDIAN_SRC/signatures/fim.db"         "$G_DST/fim.db"
cp -f "$GUARDIAN_SRC/signatures/fim.db.key"     "$G_DST/fim.db.key" 2>/dev/null || true
cp -f "$GUARDIAN_SRC/ml/anomaly.iforest"        "$G_DST/anomaly.iforest"
cp -f "$GUARDIAN_SRC/ml/anomaly.iforest.sha256" "$G_DST/anomaly.iforest.sha256"

# FIM baseline copies (clean originals for restore)
if [ -d "$GUARDIAN_SRC/baseline" ]; then
    cp -rf "$GUARDIAN_SRC/baseline/." "$G_DST/baseline/"
fi

echo "[guardian-bundle] copying config..."
cp -f "$GUARDIAN_SRC/wlt-integration/guardian.conf" "$G_DST/guardian.conf"

# vmlinux.h (generated on target, may not exist at build time — placeholder)
if [ -f "$GUARDIAN_SRC/include/vmlinux.h" ]; then
    cp -f "$GUARDIAN_SRC/include/vmlinux.h" "$G_DST/vmlinux.h"
fi

echo "[guardian-bundle] done. Files at $G_DST"
ls -la "$G_DST/"
