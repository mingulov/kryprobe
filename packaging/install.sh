#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Install kryprobe: binary + both BPF profiles + file-cap grant + verify.
#
# Usage: packaging/install.sh [--prefix PREFIX] [--destdir DIR] [--no-mint] [--stage DIR]
#   --prefix PREFIX  install root (default: /usr/local)
#   --destdir DIR    staging root prepended to all paths (packaging)
#   --no-mint        skip the root `token mint` cap grant (verify skipped too)
#   --stage DIR      install from a `build-release.sh` stage, verified
#                    first and refused before copying when inconsistent:
#                    byte-exact manifest v2 for the measured file
#                    digests, checksum list covering exactly the
#                    payload, staged binary enforcing the staged
#                    objects' named pins, installed files re-hashed after copy.
#                    Default sources are the worktree target dirs (dev
#                    flow, explicitly unverified — never a release).
#
# Tools: POSIX sh, coreutils (sha256sum, cmp), grep — no jq/python.
# The manifest template is owned by build-release.sh; format drift
# fails closed.
#
# Layout (the H-SEC-01 trusted path — the ONLY tier an elevated
# kryprobe loads from):
#   $PREFIX/bin/kryprobe
#   $PREFIX/bin/kryprobe-bpf/kcrypto.bpf.o
#   $PREFIX/bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o
#
# Requires a prior `cargo xtask build` + `cargo xtask build --bpf`,
# or a `packaging/build-release.sh --dest DIR` stage for --stage.
# Re-run after every binary swap: any replacement strips the xattr.
set -eu

PREFIX=/usr/local
DESTDIR=
MINT=1
STAGE=

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix|--destdir|--stage)
            if [ $# -lt 2 ]; then
                echo "install.sh: $1 needs a value" >&2
                exit 2
            fi
            if [ "$1" = "--prefix" ]; then PREFIX="$2";
            elif [ "$1" = "--destdir" ]; then DESTDIR="$2";
            else STAGE="$2"; fi
            shift 2
            ;;
        --no-mint) MINT=0; shift ;;
        -h|--help)
            sed -n '2,29p' "$0"
            exit 0
            ;;
        *) echo "install.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "install.sh: sha256sum not found" >&2
    exit 1
fi
if ! command -v cmp >/dev/null 2>&1; then
    echo "install.sh: cmp not found" >&2
    exit 1
fi

if [ -n "$STAGE" ]; then
    STAGE_ABS=$(CDPATH='' cd "$STAGE" && pwd) || {
        echo "install.sh: stage is not a directory: $STAGE" >&2
        exit 1
    }
    STAGE="$STAGE_ABS"
    BIN_SRC="$STAGE/bin/kryprobe"
    OBJ_SRC="$STAGE/bin/kryprobe-bpf/kcrypto.bpf.o"
    LIFECYCLE_SRC="$STAGE/bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o"
    MANIFEST="$STAGE/manifest.json"
    SUMS="$STAGE/sha256sums.txt"
    for f in "$MANIFEST" "$SUMS" "$BIN_SRC" "$OBJ_SRC" "$LIFECYCLE_SRC"; do
        if [ ! -f "$f" ]; then
            echo "install.sh: stage lacks $f" >&2
            exit 1
        fi
    done
    # Hash the actual files being copied — the checksum list and the
    # manifest are claims about these bytes, never the source of
    # truth (F04). All validation below runs before anything is
    # copied, so a refused stage leaves the destination untouched.
    BIN_DIGEST=$(sha256sum "$BIN_SRC")
    BIN_DIGEST=${BIN_DIGEST%% *}
    OBJ_DIGEST=$(sha256sum "$OBJ_SRC")
    OBJ_DIGEST=${OBJ_DIGEST%% *}
    LIFECYCLE_DIGEST=$(sha256sum "$LIFECYCLE_SRC")
    LIFECYCLE_DIGEST=${LIFECYCLE_DIGEST%% *}
    # The versioned manifest must be byte-exact manifest v2 for these
    # measured digests: no JSON parser, no fragment grep — any format
    # drift fails closed. Template owned by build-release.sh; keep
    # the two in lockstep. Compared with cmp (byte-exact, NUL-safe):
    # shell string comparison would normalize trailing newlines and
    # strip NULs.
    MANIFEST_EXPECTED=$(printf '{"kryprobe_release_manifest":2,"binary":{"path":"bin/kryprobe","sha256":"%s"},"objects":[{"name":"kcrypto.bpf.o","path":"bin/kryprobe-bpf/kcrypto.bpf.o","sha256":"%s"},{"name":"kcrypto-lifecycle.bpf.o","path":"bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o","sha256":"%s"}],"pins_enforced":true,"profile_pins_enforced":true,"pin_digests":["%s","%s"]}' "$BIN_DIGEST" "$OBJ_DIGEST" "$LIFECYCLE_DIGEST" "$OBJ_DIGEST" "$LIFECYCLE_DIGEST")
    printf '%s\n' "$MANIFEST_EXPECTED" | cmp -s - "$MANIFEST" || {
        echo "install.sh: stage manifest is not manifest v2 for these files" >&2
        exit 1
    }
    # The checksum list must cover exactly the shipped payload.
    printf '%s  bin/kryprobe\n%s  bin/kryprobe-bpf/kcrypto.bpf.o\n%s  bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o\n' \
        "$BIN_DIGEST" "$OBJ_DIGEST" "$LIFECYCLE_DIGEST" | cmp -s - "$SUMS" || {
        echo "install.sh: stage checksums do not match the payload files" >&2
        exit 1
    }
    # The staged binary itself must enforce the staged object's pin:
    # same predicate build-release.sh verifies after staging.
    STAGE_VERSIONS=$(cd / && env -u KRYPROBE_BPF_DIR -u KRYPROBE_BPF_OBJ \
        "$BIN_SRC" doctor --versions --json) || {
        echo "install.sh: staged binary doctor failed" >&2
        exit 1
    }
    echo "$STAGE_VERSIONS" | grep -q -F '"pins_enforced":true' || {
        echo "install.sh: staged binary is not pin-enforced: $STAGE_VERSIONS" >&2
        exit 1
    }
    echo "$STAGE_VERSIONS" | grep -q -F '"profile_pins_enforced":true' || {
        echo "install.sh: staged binary lacks profile-bound pins: $STAGE_VERSIONS" >&2
        exit 1
    }
    echo "$STAGE_VERSIONS" | grep -q -F "\"sha256\":\"$OBJ_DIGEST\"" || {
        echo "install.sh: staged binary does not trust the staged object: $STAGE_VERSIONS" >&2
        exit 1
    }
    echo "$STAGE_VERSIONS" | grep -q -F "\"path\":\"$OBJ_SRC\"" || {
        echo "install.sh: staged identity path mismatch: $STAGE_VERSIONS" >&2
        exit 1
    }
    echo "$STAGE_VERSIONS" | grep -q -F "\"sha256\":\"$LIFECYCLE_DIGEST\"" || {
        echo "install.sh: staged binary does not trust the staged lifecycle object: $STAGE_VERSIONS" >&2
        exit 1
    }
    echo "$STAGE_VERSIONS" | grep -q -F "\"path\":\"$LIFECYCLE_SRC\"" || {
        echo "install.sh: staged lifecycle identity path mismatch: $STAGE_VERSIONS" >&2
        exit 1
    }
else
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    echo "install.sh: dev sources, no manifest verification" >&2
    BIN_SRC="$ROOT/target/debug/kryprobe"
    OBJ_SRC="$ROOT/target/kryprobe-bpf/kcrypto.bpf.o"
    LIFECYCLE_SRC="$ROOT/target/kryprobe-bpf/kcrypto-lifecycle.bpf.o"
    [ -f "$ROOT/target/release/kryprobe" ] && BIN_SRC="$ROOT/target/release/kryprobe"
fi

if [ ! -f "$BIN_SRC" ]; then
    echo "install.sh: missing $BIN_SRC (run \`cargo xtask build\` first)" >&2
    exit 1
fi
for source in "$OBJ_SRC" "$LIFECYCLE_SRC"; do
    if [ ! -f "$source" ]; then
        echo "install.sh: missing $source (run \`cargo xtask build --bpf\` first)" >&2
        exit 1
    fi
done

BIN_DST="$DESTDIR$PREFIX/bin/kryprobe"
OBJ_DIR="$DESTDIR$PREFIX/bin/kryprobe-bpf"
OBJ_DST="$OBJ_DIR/kcrypto.bpf.o"
LIFECYCLE_DST="$OBJ_DIR/kcrypto-lifecycle.bpf.o"

mkdir -p "$(dirname -- "$BIN_DST")" "$OBJ_DIR"
cp -f "$BIN_SRC" "$BIN_DST"
cp -f "$OBJ_SRC" "$OBJ_DST"
cp -f "$LIFECYCLE_SRC" "$LIFECYCLE_DST"
chmod 0755 "$BIN_DST"
chmod 0644 "$OBJ_DST" "$LIFECYCLE_DST"
echo "+ installed $BIN_DST"
echo "+ installed $OBJ_DST"
echo "+ installed $LIFECYCLE_DST"
if [ -n "$STAGE" ]; then
    # Confirm all destination files match the verified stage before
    # declaring success (F04). On mismatch the destination may hold
    # a corrupt pair: re-run from a valid stage (no auto-recovery).
    INST_BIN_DIGEST=$(sha256sum "$BIN_DST")
    INST_BIN_DIGEST=${INST_BIN_DIGEST%% *}
    INST_OBJ_DIGEST=$(sha256sum "$OBJ_DST")
    INST_OBJ_DIGEST=${INST_OBJ_DIGEST%% *}
    INST_LIFECYCLE_DIGEST=$(sha256sum "$LIFECYCLE_DST")
    INST_LIFECYCLE_DIGEST=${INST_LIFECYCLE_DIGEST%% *}
    if [ "$INST_BIN_DIGEST" != "$BIN_DIGEST" ] || [ "$INST_OBJ_DIGEST" != "$OBJ_DIGEST" ] || [ "$INST_LIFECYCLE_DIGEST" != "$LIFECYCLE_DIGEST" ]; then
        echo "install.sh: installed files do not match the verified stage" >&2
        exit 1
    fi
    echo "+ verified $BIN_DST"
    echo "+ verified $OBJ_DST"
    echo "+ verified $LIFECYCLE_DST"
fi

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
