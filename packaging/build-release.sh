#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Pinned release stage: BPF objects, digest-pinned release binary,
# atomic stage dir, manifest + hashes, doctor verify.
#
# Usage: packaging/build-release.sh --dest DIR [--cargo CARGO]
#   --dest DIR     owned staging directory (must be absent or empty)
#   --cargo CARGO  cargo binary (default: $CARGO or cargo from PATH)
#
# Two-phase order -- never rebuild objects after pinning without
# rebuilding the host binary (the pin would name bytes that no
# longer exist):
#   1. cargo xtask build --bpf
#   2. digest target/kryprobe-bpf/kcrypto.bpf.o
#   3. KRYPROBE_REQUIRE_PINS=1 KRYPROBE_PIN_DIGESTS=<digest>
#        cargo build --locked --release -p kryprobe-cli
#   4. stage binary + object atomically, write manifest + sha256sums
#   5. verify staged doctor --versions: pins_enforced + digest match
#
# Stage layout (installed verbatim by install.sh --stage):
#   $DEST/bin/kryprobe
#   $DEST/bin/kryprobe-bpf/kcrypto.bpf.o
#   $DEST/manifest.json
#   $DEST/sha256sums.txt
#
# Future lifecycle objects join the manifest explicitly, never via an
# unbounded directory glob.
set -eu

DEST=
CARGO_BIN=${CARGO:-cargo}

while [ $# -gt 0 ]; do
    case "$1" in
        --dest)
            if [ $# -lt 2 ]; then
                echo "build-release.sh: --dest needs a value" >&2
                exit 2
            fi
            DEST="$2"
            shift 2
            ;;
        --cargo)
            if [ $# -lt 2 ]; then
                echo "build-release.sh: --cargo needs a value" >&2
                exit 2
            fi
            CARGO_BIN="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,24p' "$0"
            exit 0
            ;;
        *) echo "build-release.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

if [ -z "$DEST" ]; then
    echo "build-release.sh: --dest DIR is required" >&2
    exit 2
fi
if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
    echo "build-release.sh: cargo not found: $CARGO_BIN" >&2
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "build-release.sh: sha256sum not found" >&2
    exit 1
fi
if [ -e "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
    echo "build-release.sh: refusing non-empty dest: $DEST" >&2
    exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OBJ_SRC="$ROOT/target/kryprobe-bpf/kcrypto.bpf.o"
BIN_SRC="$ROOT/target/release/kryprobe"

echo "+ phase 1: BPF objects"
( unset CARGO_TARGET_DIR; cd "$ROOT" && "$CARGO_BIN" xtask build --bpf )

if [ ! -f "$OBJ_SRC" ]; then
    echo "build-release.sh: missing $OBJ_SRC after xtask build --bpf" >&2
    exit 1
fi
DIGEST=$(sha256sum "$OBJ_SRC")
DIGEST=${DIGEST%% *}
case "$DIGEST" in
    *[!0-9a-f]*|"")
        echo "build-release.sh: bad digest: $DIGEST" >&2
        exit 1
        ;;
esac
if [ "${#DIGEST}" -ne 64 ]; then
    echo "build-release.sh: bad digest length: $DIGEST" >&2
    exit 1
fi
echo "+ object digest: $DIGEST"

echo "+ phase 2: pinned release binary"
cd "$ROOT"
KRYPROBE_REQUIRE_PINS=1 KRYPROBE_PIN_DIGESTS="$DIGEST" \
    "$CARGO_BIN" build --locked --release -p kryprobe-cli

if [ ! -f "$BIN_SRC" ]; then
    echo "build-release.sh: missing $BIN_SRC after release build" >&2
    exit 1
fi

echo "+ staging into $DEST"
STAGE_TMP=$(mktemp -d "${DEST}.tmp.XXXXXX")
trap 'rm -rf "$STAGE_TMP"' EXIT INT TERM
mkdir -p "$STAGE_TMP/bin/kryprobe-bpf"
cp -f "$BIN_SRC" "$STAGE_TMP/bin/kryprobe"
cp -f "$OBJ_SRC" "$STAGE_TMP/bin/kryprobe-bpf/kcrypto.bpf.o"
chmod 0755 "$STAGE_TMP/bin/kryprobe"
chmod 0644 "$STAGE_TMP/bin/kryprobe-bpf/kcrypto.bpf.o"
BIN_DIGEST=$(sha256sum "$STAGE_TMP/bin/kryprobe")
BIN_DIGEST=${BIN_DIGEST%% *}
OBJ_DIGEST=$(sha256sum "$STAGE_TMP/bin/kryprobe-bpf/kcrypto.bpf.o")
OBJ_DIGEST=${OBJ_DIGEST%% *}
if [ "$OBJ_DIGEST" != "$DIGEST" ]; then
    echo "build-release.sh: staged object digest drifted ($OBJ_DIGEST != $DIGEST)" >&2
    exit 1
fi
(cd "$STAGE_TMP" && sha256sum bin/kryprobe bin/kryprobe-bpf/kcrypto.bpf.o > sha256sums.txt)
cat > "$STAGE_TMP/manifest.json" <<EOF
{"kryprobe_release_manifest":1,"binary":{"path":"bin/kryprobe","sha256":"$BIN_DIGEST"},"objects":[{"name":"kcrypto.bpf.o","path":"bin/kryprobe-bpf/kcrypto.bpf.o","sha256":"$OBJ_DIGEST"}],"pins_enforced":true,"pin_digests":["$DIGEST"]}
EOF
chmod 0644 "$STAGE_TMP/manifest.json" "$STAGE_TMP/sha256sums.txt"

echo "+ verifying staged doctor --versions"
VERSIONS=$(cd / && env -u KRYPROBE_BPF_DIR -u KRYPROBE_BPF_OBJ \
    "$STAGE_TMP/bin/kryprobe" doctor --versions --json) \
    || { echo "build-release.sh: staged doctor --versions failed" >&2; exit 1; }
echo "$VERSIONS" | grep -q -F '"pins_enforced":true' \
    || { echo "build-release.sh: staged binary is not pin-enforced: $VERSIONS" >&2; exit 1; }
echo "$VERSIONS" | grep -q -F "\"sha256\":\"$DIGEST\"" \
    || { echo "build-release.sh: staged identity digest mismatch: $VERSIONS" >&2; exit 1; }
echo "$VERSIONS" | grep -q -F "\"path\":\"$STAGE_TMP/bin/kryprobe-bpf/kcrypto.bpf.o\"" \
    || { echo "build-release.sh: staged identity path mismatch: $VERSIONS" >&2; exit 1; }

if [ -e "$DEST" ]; then
    rmdir "$DEST" 2>/dev/null || {
        echo "build-release.sh: dest became non-empty: $DEST" >&2
        exit 1
    }
fi
mv "$STAGE_TMP" "$DEST"
trap - EXIT INT TERM
echo "+ staged $DEST"
echo "+ manifest: $DEST/manifest.json"
cat "$DEST/manifest.json"
echo
