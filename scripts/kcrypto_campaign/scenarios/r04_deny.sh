#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R04-deny guest cell: the disabled observation (report --system
# as an unprivileged user must refuse typed exit 4) plus the
# privileged aggregate control (hash n=10, ftrace kernel reference).
# $1 = staged out dir.
set -u
OUT="$1"
. "$OUT/pins.env"
. "$OUT/ftrace_ref.sh"
export KRYPROBE_BPF_DIR="$OUT/kryprobe-bpf"
KP="$OUT/kryprobe"
FAIL=0

wait_attach() {
  i=0
  while [ "$i" -lt 60 ]; do
    if grep -q '"audit":"attach"' "$1" 2>/dev/null; then
      echo "attach_ready_s=$i" > "$2"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "attach_ready_s=TIMEOUT" > "$2"
  return 1
}

{
  echo "kernel=$(uname -r)"
  echo "uid=$(id -u)"
  echo "head=$(cat "$OUT/head-sha.txt")"
  echo "ko=none"
  echo "obj_agg=$(sha256sum "$OUT/kryprobe-bpf/kcrypto.bpf.o" | cut -d' ' -f1)"
  echo "obj_lc=$(sha256sum "$OUT/kryprobe-bpf/kcrypto-lifecycle.bpf.o" | cut -d' ' -f1)"
  echo "kryprobe=$(sha256sum "$OUT/kryprobe" | cut -d' ' -f1)"
  echo "fixture=$(sha256sum "$OUT/kcrypto_gen.py" | cut -d' ' -f1)"
} > "$OUT/environment.txt" 2>&1
ls /sys/kernel/btf/ > "$OUT/btf-objs.txt" 2>&1
{
  echo "kernel=$(uname -r)"
  echo "config_sha=$(sha256sum "$OUT/guest-config" | cut -d' ' -f1)"
  echo "btf_sha=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)"
  echo "module_sha=$MODULE_SHA"
  echo "cli_sha=$CLI_SHA"
  echo "bpf_agg_sha=$BPF_AGG_SHA"
  echo "bpf_lc_sha=$BPF_LC_SHA"
  echo "oracle_sha=$ORACLE_SHA"
} > "$OUT/identity-before.env" 2>&1

modprobe algif_hash 2>/dev/null

# Refusal leg: world-readable copies (the staged dir is root-only),
# then drop all privilege for the capture attempt.
mkdir -p "$OUT/unpriv/kryprobe-bpf"
cp "$OUT/kryprobe" "$OUT/unpriv/kryprobe"
cp "$OUT/kryprobe-bpf/kcrypto.bpf.o" "$OUT/unpriv/kryprobe-bpf/kcrypto.bpf.o"
cp "$OUT/kryprobe-bpf/kcrypto-lifecycle.bpf.o" "$OUT/unpriv/kryprobe-bpf/kcrypto-lifecycle.bpf.o"
chmod -R a+rX "$OUT/unpriv"
echo "unpriv_sha=$(sha256sum "$OUT/unpriv/kryprobe" | cut -d' ' -f1)" > "$OUT/unpriv-sha.txt"
# --out points at world-writable /tmp: the staged dir is root-only
# and an --out precheck failure (exit 1) would mask the capability
# refusal (exit 4) under test.
KRYPROBE_BPF_DIR="$OUT/unpriv/kryprobe-bpf" setpriv --reuid=65534 --regid=65534 --clear-groups \
  "$OUT/unpriv/kryprobe" report --system --duration 5 --format json \
  --out /tmp/t13-refusal.json 2> "$OUT/refusal-stderr.log"
echo "refusal_rc=$?" > "$OUT/refusal-rc.txt"
cp /tmp/t13-refusal.json "$OUT/refusal.json" 2>/dev/null || echo "no refusal.json (bring-up refused)" > "$OUT/refusal.json"
rm -f /tmp/t13-refusal.json

# Control leg: privileged capture + ftrace window + fixture traffic.
"$KP" report --system --format json --duration 60 --out "$OUT/control.json" \
  2> "$OUT/control.stderr.log" &
CAP=$!
wait_attach "$OUT/control.stderr.log" "$OUT/control-attach.txt" || FAIL=1
ftrace_begin "crypto_ahash_digest crypto_shash_digest" || FAIL=1
python3 -c "
import sys
sys.path.insert(0, '$OUT')
import kcrypto_gen
kcrypto_gen.hash_burst(n=10)
print('generator finished', flush=True)
" > "$OUT/control-stdout.log" 2>&1
echo "control_rc=$?" > "$OUT/control-rc.txt"
# shellcheck disable=SC2034
ftrace_end crypto_ahash_digest crypto_shash_digest > "$OUT/kernel-counts.txt" 2>&1 || FAIL=1
wait "$CAP"
rc=$?
echo "capture_rc=$rc" > "$OUT/control-cap-rc.txt"
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then FAIL=1; fi
python3 -c "
import json
counts = {}
for line in open('$OUT/kernel-counts.txt'):
    name, _, value = line.partition(' ')
    counts[name.strip()] = int(value.strip())
json.dump({'method': 'trace_stat/functions', 'main': counts},
          open('$OUT/kernel-ref.json', 'w'), indent=2)
" || FAIL=1

dmesg | tail -5 > "$OUT/dmesg-tail.txt" 2>&1
{
  echo "kernel=$(uname -r)"
  echo "config_sha=$(sha256sum "$OUT/guest-config" | cut -d' ' -f1)"
  echo "btf_sha=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)"
  echo "module_sha=$MODULE_SHA"
  echo "cli_sha=$CLI_SHA"
  echo "bpf_agg_sha=$BPF_AGG_SHA"
  echo "bpf_lc_sha=$BPF_LC_SHA"
  echo "oracle_sha=$ORACLE_SHA"
} > "$OUT/identity-after.env" 2>&1
ftrace_cleanup_marker "$OUT/cleanup.txt"
echo "step=done" > "$OUT/done.txt"
exit "$FAIL"
