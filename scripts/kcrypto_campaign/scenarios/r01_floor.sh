#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R01-floor guest cell (6.12.111): supported aggregate leg
# (hash n=20 + skcipher n=10 via the staged repo fixture, ftrace
# kernel reference) plus the typed request-lifecycle refusal leg.
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
modprobe algif_skcipher 2>/dev/null

# Aggregate leg: capture + ftrace window around the fixture run.
"$KP" report --system --format json --duration 60 --out "$OUT/aggregate.json" \
  2> "$OUT/aggregate.stderr.log" &
CAP=$!
wait_attach "$OUT/aggregate.stderr.log" "$OUT/aggregate-attach.txt" || FAIL=1
ftrace_begin "crypto_ahash_digest crypto_shash_digest crypto_skcipher_encrypt crypto_skcipher_decrypt" \
  || FAIL=1
python3 -c "
import sys
sys.path.insert(0, '$OUT')
sys.argv = ['kcrypto_gen.py']
import kcrypto_gen
kcrypto_gen.hash_burst(n=20)
kcrypto_gen.skcipher_burst(n=10)
print('generator finished', flush=True)
" > "$OUT/workload-stdout.log" 2>&1
echo "workload_rc=$?" > "$OUT/workload-rc.txt"
# shellcheck disable=SC2034
ftrace_end crypto_ahash_digest crypto_shash_digest crypto_skcipher_encrypt crypto_skcipher_decrypt \
  > "$OUT/kernel-counts.txt" 2>&1 || FAIL=1
wait "$CAP"
rc=$?
echo "capture_rc=$rc" > "$OUT/aggregate-rc.txt"
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

# Refusal leg: request-lifecycle must refuse typed (exit 4).
"$KP" report --system --kcrypto-profile request-lifecycle --duration 5 \
  --format json --out "$OUT/refusal.json" 2> "$OUT/refusal-stderr.log"
echo "refusal_rc=$?" > "$OUT/refusal-rc.txt"

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
