#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Install kryprobe: binary + bundled BPF object + file-cap grant + verify.
#
# Usage: packaging/install.sh [--prefix PREFIX] [--destdir DIR] [--no-mint]
#   --prefix PREFIX  install root (default: /usr/local)
#   --destdir DIR    staging root prepended to all paths (packaging)
#   --no-mint        skip the root `token mint` cap grant (verify skipped too)
#
# Layout (the H-SEC-01 trusted path — the ONLY tier an elevated
# kryprobe loads from):
#   $PREFIX/bin/kryprobe
#   $PREFIX/bin/kryprobe-bpf/kcrypto.bpf.o
#
# Requires a prior `cargo xtask build` + `cargo xtask build --bpf`.
# Re-run after every binary swap: any replacement strips the xattr.
set -eu

PREFIX=/usr/local
DESTDIR=
MINT=1

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix|--destdir)
            if [ $# -lt 2 ]; then
                echo "install.sh: $1 needs a value" >&2
                exit 2
            fi
            if [ "$1" = "--prefix" ]; then PREFIX="$2"; else DESTDIR="$2"; fi
            shift 2
            ;;
        --no-mint) MINT=0; shift ;;
        -h|--help)
            sed -n '2,12p' "$0"
            exit 0
            ;;
        *) echo "install.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN_SRC="$ROOT/target/debug/kryprobe"
OBJ_SRC="$ROOT/target/kryprobe-bpf/kcrypto.bpf.o"
[ -f "$ROOT/target/release/kryprobe" ] && BIN_SRC="$ROOT/target/release/kryprobe"

if [ ! -f "$BIN_SRC" ]; then
    echo "install.sh: missing $BIN_SRC (run \`cargo xtask build\` first)" >&2
    exit 1
fi
if [ ! -f "$OBJ_SRC" ]; then
    echo "install.sh: missing $OBJ_SRC (run \`cargo xtask build --bpf\` first)" >&2
    exit 1
fi

BIN_DST="$DESTDIR$PREFIX/bin/kryprobe"
OBJ_DIR="$DESTDIR$PREFIX/bin/kryprobe-bpf"
OBJ_DST="$OBJ_DIR/kcrypto.bpf.o"

mkdir -p "$(dirname -- "$BIN_DST")" "$OBJ_DIR"
cp -f "$BIN_SRC" "$BIN_DST"
cp -f "$OBJ_SRC" "$OBJ_DST"
chmod 0755 "$BIN_DST"
chmod 0644 "$OBJ_DST"
echo "+ installed $BIN_DST"
echo "+ installed $OBJ_DST"

if [ "$MINT" -eq 0 ]; then
    echo "install.sh: --no-mint, skipping cap grant + verify" >&2
    exit 0
fi
if [ -n "$DESTDIR" ]; then
    echo "install.sh: DESTDIR staging, skipping live cap grant + verify" >&2
    exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: not root, skipping \`token mint\`; run as root:" >&2
    echo "  $BIN_DST token mint --bin $BIN_DST" >&2
    exit 0
fi

"$BIN_DST" token mint --bin "$BIN_DST" \
    || { echo "install.sh: token mint failed" >&2; exit 1; }
echo "+ file caps granted; verifying"
"$BIN_DST" token status --bin "$BIN_DST"
"$BIN_DST" doctor | grep -E "^probe (kcrypto_object|kcrypto_attach|cap_state):" \
    || { echo "install.sh: doctor verify failed" >&2; exit 1; }
echo "+ install verified"
