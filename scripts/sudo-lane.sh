#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# 4B-H2: the privileged lane as one command. Runs the unprivileged BPF
# lane (`cargo xtask test bpf`: build objects + fixture, honest-denial
# asserts), then the strict privileged asserts: the sudo selftests
# plus every `#[ignore]`d suite test in the workspace (each test
# binary's `--ignored` set under sudo). Until the self-hosted
# privileged runner exists, schedule this by hand with the lane lock.
#
# Usage: scripts/sudo-lane.sh
# Knobs: KRYPROBE_LANE_LOCK (default /tmp/kryprobe-bpf-lane.lock),
#   KRYPROBE_BPF_CALLS (default 20000, selftest traffic volume).
# Exits: 0 all green; 1 a lane step failed; 4 lane unavailable
#   (no root/passwordless sudo, or the lock is held) — record NOT_RUN.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
LOCK=${KRYPROBE_LANE_LOCK:-/tmp/kryprobe-bpf-lane.lock}
CALLS=${KRYPROBE_BPF_CALLS:-20000}

# Serialize on the host-global BPF lane lock (ambient map/program
# churn fails leak comparisons honestly rather than silently).
if [ -z "${KRYPROBE_LANE_HELD:-}" ]; then
    export KRYPROBE_LANE_HELD=1
    exec flock "$LOCK" "$0" "$@"
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
else
    echo "NOT_RUN sudo-lane: need root or passwordless sudo" >&2
    exit 4
fi

fail=0
step() {
    echo "--- sudo-lane: $1"
    if ! eval "$2"; then
        echo "FAIL: $1" >&2
        fail=1
    fi
}

step "host build" "cargo xtask build"
step "BPF objects" "cargo xtask build --bpf"
# G9: elevated runs only trust the exe tier (`<exe-dir>/kryprobe-bpf/`;
# env/CWD tiers are refused when elevated). Stage the just-built
# object where both consumer shapes look: beside the kryprobe binary
# (spawned children) and beside the test binaries (in-process suites).
step "stage exe-tier objects" "mkdir -p target/debug/kryprobe-bpf target/debug/deps/kryprobe-bpf && cp target/kryprobe-bpf/kcrypto.bpf.o target/debug/kryprobe-bpf/kcrypto.bpf.o && cp target/kryprobe-bpf/kcrypto.bpf.o target/debug/deps/kryprobe-bpf/kcrypto.bpf.o"
step "BPF lane (unprivileged asserts)" "cargo xtask test bpf"
step "selftest bpf" "$SUDO ./target/debug/kryprobe selftest bpf --calls $CALLS"
step "selftest token-smoke" "$SUDO ./target/debug/kryprobe selftest token-smoke"

# Strict privileged asserts: every workspace test binary's ignored
# set, newest binary per tests/*.rs source (deps/ keeps stale
# hashes across rebuilds, so never glob it blindly).
step "suite binaries" "cargo test --locked --workspace --no-run"
for src in crates/*/tests/*.rs; do
    stem=$(basename "$src" .rs | tr '-' '_')
    bin=$(ls -t "target/debug/deps/$stem"-* 2>/dev/null | grep -v '\.' | head -n 1 || true)
    if [ -z "${bin:-}" ] || [ ! -x "$bin" ]; then
        echo "FAIL: no test binary for $src" >&2
        fail=1
        continue
    fi
    # Unquoted $SUDO: empty when root, `sudo -n` otherwise.
    # shellcheck disable=SC2086
    if ! $SUDO "./$bin" --ignored --format terse; then
        echo "FAIL: $stem --ignored" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "sudo-lane: FAILURES present (see FAIL lines above)" >&2
    exit 1
fi
echo "sudo-lane: all green"
