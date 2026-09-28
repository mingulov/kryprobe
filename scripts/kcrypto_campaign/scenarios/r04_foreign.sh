#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R04-foreign guest cell: owned hash workload (n=20, PIDs
# recorded) plus foreign hash traffic (n=6, PIDs recorded, same
# comm) under one capture; the oracle requires unique owned
# correspondence (exact 20:6 who ratio + full agg coverage).
# $1 = staged out dir.
set -u
OUT="$1"
. "$OUT/pins.env"
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

"$KP" report --system --format json --duration 60 --out "$OUT/product.json" \
  2> "$OUT/capture.stderr.log" &
CAP=$!
wait_attach "$OUT/capture.stderr.log" "$OUT/capture-attach.txt" || FAIL=1

# Owned workload first (PID + start-tick recorded for no-reuse).
python3 -c "
import sys
sys.path.insert(0, '$OUT')
import kcrypto_gen
kcrypto_gen.hash_burst(n=20)
print('generator finished', flush=True)
" > "$OUT/owned-stdout.log" 2>&1 &
OWNED=$!
echo "$OWNED $(awk '{print $22}' /proc/$OWNED/stat 2>/dev/null)" > "$OUT/owned-pid.txt"
wait "$OWNED"
echo "owned_rc=$?" > "$OUT/owned-rc.txt"

# Foreign decoy second (same comm, distinct recorded PID).
python3 -c "
import sys
sys.path.insert(0, '$OUT')
import kcrypto_gen
kcrypto_gen.hash_burst(n=6)
print('generator finished', flush=True)
" > "$OUT/foreign-stdout.log" 2>&1 &
FOREIGN=$!
echo "$FOREIGN $(awk '{print $22}' /proc/$FOREIGN/stat 2>/dev/null)" > "$OUT/foreign-pid.txt"
wait "$FOREIGN"
echo "foreign_rc=$?" > "$OUT/foreign-rc.txt"

wait "$CAP"
rc=$?
echo "capture_rc=$rc" > "$OUT/capture-rc.txt"
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then FAIL=1; fi

python3 -c "
import json
def pidfile(path):
    pid, _, ticks = open(path).read().strip().partition(' ')
    return int(pid), ticks.strip()
opid, oticks = pidfile('$OUT/owned-pid.txt')
fpid, fticks = pidfile('$OUT/foreign-pid.txt')
json.dump({'pids': [opid], 'start_ticks': [oticks]},
          open('$OUT/owned-pids.json', 'w'))
json.dump({'pids': [fpid], 'start_ticks': [fticks]},
          open('$OUT/foreign-pids.json', 'w'))
print('owned=%d foreign=%d' % (opid, fpid))
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
: > "$OUT/cleanup.txt"
echo "step=done" > "$OUT/done.txt"
exit "$FAIL"
