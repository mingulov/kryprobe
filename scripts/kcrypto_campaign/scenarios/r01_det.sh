#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R01-det guest cell: the same sync-once fixture run twice
# (fresh module load per leg); the api-returns capture per leg
# must be semantically identical and both ledgers must validate
# on the host. $1 = staged out dir.
set -u
OUT="$1"
. "$OUT/pins.env"
export KRYPROBE_BPF_DIR="$OUT/kryprobe-bpf"
KP="$OUT/kryprobe"
FIX=/sys/kernel/debug/kcrypto_fixture
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
  echo "ko=$(sha256sum "$OUT/kcrypto_fixture.ko" | cut -d' ' -f1)"
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

run_leg() {
  leg="$1"
  runid="$2"
  insmod "$OUT/kcrypto_fixture.ko" run_suffix="$PORTION" > "$OUT/insmod-$leg.log" 2>&1
  echo "insmod_rc=$?" > "$OUT/insmod-$leg-rc.txt"
  "$KP" report --system --format json --duration 30 --out "$OUT/report-$leg.json" \
    2> "$OUT/capture-$leg.stderr.log" &
  CAP=$!
  wait_attach "$OUT/capture-$leg.stderr.log" "$OUT/capture-$leg-attach.txt" || FAIL=1
  # shellcheck disable=SC2034
  echo "PREPARE $runid sync-once 42" > "$FIX/control" 2> "$OUT/prepare-$leg.err" || FAIL=1
  cat "$FIX/control" > "$OUT/status-$leg.txt" 2>&1
  echo GO > "$FIX/control" 2> "$OUT/go-$leg.err" || FAIL=1
  wait "$CAP"
  rc=$?
  echo "capture_rc=$rc" > "$OUT/capture-$leg-rc.txt"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then FAIL=1; fi
  cat "$FIX/control" > "$OUT/control-$leg-final.txt" 2>&1
  cp "$FIX/ledger" "$OUT/ledger-$leg.jsonl" 2>/dev/null || FAIL=1
  rmmod kcrypto_fixture >> "$OUT/insmod-$leg.log" 2>&1
  echo "rmmod_rc=$?" >> "$OUT/insmod-$leg-rc.txt"
}

run_leg legA t13r01a
run_leg legB t13r01b

lsmod | grep -c kcrypto_fixture > "$OUT/lsmod-after.txt" 2>&1 || echo 0 > "$OUT/lsmod-after.txt"
dmesg | grep -E "kcrypto_fixture|kxcipher" | tail -5 > "$OUT/dmesg-tail.txt" 2>&1
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
if [ "$(cat "$OUT/lsmod-after.txt")" = "0" ] && [ ! -e "$FIX/control" ]; then
  echo "module=1" > "$OUT/cleanup.txt"
else
  echo "module=0" > "$OUT/cleanup.txt"
fi
echo "step=done" > "$OUT/done.txt"
exit "$FAIL"
