#!/usr/bin/env bash
# Phase 1.3: build-baseline.sh — copies watched files into the FIM baseline dir.
#
# The baseline directory holds CLEAN ORIGINAL copies of watched files so that
# g_action_restore_file() can restore them after tampering. The quarantine dir
# holds MALICIOUS files (not clean originals), so it cannot be used for restore.
#
# Usage:
#   ./scripts/build-baseline.sh <paths-file> [baseline-dir]
#
# paths-file: newline-separated list of absolute paths to snapshot (e.g. /etc/passwd)
# baseline-dir: defaults to /etc/wlt/guardian/baseline/
#
# The escaped filename is the path with leading '/' stripped and each '/' -> '__'.
# So /etc/passwd  ->  etc__passwd
set -euo pipefail

PATHS_FILE="${1:-/etc/wlt/guardian/watched-paths.txt}"
BASELINE_DIR="${2:-/etc/wlt/guardian/baseline}"

if [ ! -f "$PATHS_FILE" ]; then
    echo "[build-baseline] paths file not found: $PATHS_FILE" >&2
    exit 1
fi

mkdir -p "$BASELINE_DIR"
chmod 0700 "$BASELINE_DIR"

n=0
fail=0
while IFS= read -r line; do
    # strip comments + whitespace
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [ -z "$line" ] && continue
    [ ! -e "$line" ] && { echo "[build-baseline] skip (missing): $line" >&2; fail=$((fail+1)); continue; }

    # escape: strip leading /, replace / with __
    esc="${line#/}"
    esc="${esc//\//__}"

    if [ -f "$line" ]; then
        cp -a "$line" "$BASELINE_DIR/$esc"
        n=$((n+1))
    elif [ -d "$line" ]; then
        # shallow copy of directory contents
        mkdir -p "$BASELINE_DIR/$esc"
        cp -a "$line/." "$BASELINE_DIR/$esc/" 2>/dev/null || true
        n=$((n+1))
    fi
done < "$PATHS_FILE"

echo "[build-baseline] copied $n paths to $BASELINE_DIR ($fail skipped)"
echo "[build-baseline] these clean originals are used by g_action_restore_file()"
