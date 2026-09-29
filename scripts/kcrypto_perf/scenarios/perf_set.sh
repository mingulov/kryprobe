#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T14 P9 perf pair-set guest cell: one boot runs a quiet leg plus the
# staged legs.tsv rows (leg_id, side, mode, cls, driver, size,
# workload, paced, bulk, threads). Modes: disabled (driver only),
# aggregation (api-returns capture), full-details (request-lifecycle
# capture), attached-idle (capture, no driver). $1 = staged out dir.
# Exit 0: all legs attempted; exit 2: set abort (ambient traffic,
# attach timeout, or module failure) — host seals partial, verify
# marks the set INVALID (never retried into green).
set -u
OUT="$1"
. "$OUT/pins.env"
. "$OUT/set.env"
export KRYPROBE_BPF_DIR="$OUT/kryprobe-bpf"
KP="$OUT/kryprobe"
D="$OUT/kcrypto_perf.py"
FIX=/sys/kernel/debug/kcrypto_fixture
FAIL=0
mkdir -p "$OUT/legs"

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

sampler() {
  pid="$1"
  out="$2"
  echo "clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)" > "$out"
  while kill -0 "$pid" 2>/dev/null; do
    rss=$(awk '/VmRSS/{print $2; exit}' /proc/"$pid"/status 2>/dev/null)
    stats=$(sed 's/.*) //' /proc/"$pid"/stat 2>/dev/null)
    ut=$(echo "$stats" | awk '{print $12}')
    st=$(echo "$stats" | awk '{print $13}')
    # Skip torn reads (exiting process): a zero sample would fake
    # negative CPU deltas downstream. No sample beats a false one.
    case "$rss" in ''|*[!0-9]*) sleep 1; continue;; esac
    case "$ut" in ''|*[!0-9]*) sleep 1; continue;; esac
    case "$st" in ''|*[!0-9]*) sleep 1; continue;; esac
    echo "t=$(date +%s) rss_kb=$rss utime=$ut stime=$st" >> "$out"
    sleep 1
  done
}

{
  echo "kernel=$(uname -r)"
  echo "uid=$(id -u)"
  echo "head=$(cat "$OUT/head-sha.txt")"
  echo "nproc=$(nproc)"
  echo "mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  echo "ko=$(sha256sum "$OUT/kcrypto_fixture.ko" 2>/dev/null | cut -d' ' -f1)"
  echo "obj_agg=$(sha256sum "$OUT/kryprobe-bpf/kcrypto.bpf.o" | cut -d' ' -f1)"
  echo "obj_lc=$(sha256sum "$OUT/kryprobe-bpf/kcrypto-lifecycle.bpf.o" | cut -d' ' -f1)"
  echo "kryprobe=$(sha256sum "$OUT/kryprobe" | cut -d' ' -f1)"
  echo "driver=$(sha256sum "$D" | cut -d' ' -f1)"
  echo "wmem_max=$(cat /proc/sys/net/core/wmem_max)"
  echo "rmem_max=$(cat /proc/sys/net/core/rmem_max)"
} > "$OUT/environment.txt" 2>&1
ls /sys/kernel/btf/ > "$OUT/btf-objs.txt" 2>&1
grep -m1 "model name" /proc/cpuinfo > "$OUT/cpu-model.txt" 2>&1
sysctl -w net.core.wmem_max=8388608 net.core.rmem_max=8388608 \
  > "$OUT/sysctl.log" 2>&1 || FAIL=1
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

if [ "$NEED_MODULE" = "1" ]; then
  insmod "$OUT/kcrypto_fixture.ko" run_suffix="$SET_ID" \
    > "$OUT/insmod.log" 2>&1
  echo "insmod_rc=$?" > "$OUT/insmod-rc.txt"
  if [ "$(cat "$OUT/insmod-rc.txt" | cut -d= -f2)" != "0" ]; then
    echo "FAIL=module" > "$OUT/done.txt"
    exit 2
  fi
fi

run_driver() {
  # $1 = leg id, $2.. driver args; records rc + timeout flag.
  leg="$1"
  shift
  # shellcheck disable=SC2086
  timeout -s TERM 150 python3 "$D" "$@" "$OUT/legs/$leg-driver.csv" \
    > "$OUT/legs/$leg-driver.stdout.log" \
    2> "$OUT/legs/$leg-driver.stderr.log"
  rc=$?
  timed=0
  if [ "$rc" -eq 124 ]; then timed=1; fi
  echo "driver_rc=$rc" > "$OUT/legs/$leg-driver-rc.txt"
  echo "driver_timeout=$timed" >> "$OUT/legs/$leg-driver-rc.txt"
  return 0
}

CAP_PID=""
start_capture() {
  # $1 = leg id, $2 = profile, $3 = format. Sets $CAP_PID in the
  # MAIN shell (never via $(...) — a substitution would hold the
  # stdout pipe open and block until the capture ends, running the
  # driver after the window instead of inside it).
  leg="$1"
  profile_args=""
  if [ "$2" = "request-lifecycle" ]; then
    profile_args="--kcrypto-profile request-lifecycle"
  fi
  # shellcheck disable=SC2086
  "$KP" report --system $profile_args --duration "$CAPTURE_S" \
    --format "$3" --out "$OUT/legs/$leg-report.$3" \
    > "$OUT/legs/$leg-capture.stdout.log" \
    2> "$OUT/legs/$leg-capture.stderr.log" &
  CAP_PID=$!
}

# Quiet leg: any ambient crypto traffic aborts the boot (fast fail —
# a polluted boot cannot yield equivalent-work pairs).
echo "quiet_start=$(date +%s)" > "$OUT/quiet-wall.txt"
"$KP" report --system --format json --duration "$QUIET_S" \
  --out "$OUT/quiet-report.json" 2> "$OUT/quiet-capture.stderr.log" &
QCAP=$!
wait_attach "$OUT/quiet-capture.stderr.log" "$OUT/quiet-attach.txt" || FAIL=1
wait "$QCAP"
echo "capture_rc=$?" > "$OUT/quiet-rc.txt"
echo "quiet_end=$(date +%s)" >> "$OUT/quiet-wall.txt"
QUIET_CALLS=$(python3 -c "
import json
d = json.load(open('$OUT/quiet-report.json'))
for o in d['observations']:
    p = o['backend_payload']
    if p.get('row') == 'totals':
        print(p['counts']['calls'])
" 2>/dev/null || echo "PARSE_FAIL")
echo "quiet_calls=$QUIET_CALLS" > "$OUT/quiet-calls.txt"
if [ "$QUIET_CALLS" != "0" ]; then
  echo "FAIL=ambient" > "$OUT/done.txt"
  exit 2
fi

LEG_DONE=0
while IFS="$(printf '\t')" read -r leg side mode cls driver size \
    workload paced bulk threads; do
  case "$leg" in ""|"#"*) continue;; esac
  echo "leg_start=$(date +%s)" > "$OUT/legs/$leg-wall.txt"
  extra=""
  if [ "$bulk" = "1" ]; then extra="$extra --bulk"; fi
  if [ "$paced" != "0" ]; then extra="$extra --paced $paced"; fi
  if [ "$threads" != "1" ]; then extra="$extra --threads $threads"; fi
  case "$mode" in
    disabled)
      # shellcheck disable=SC2086
      run_driver "$leg" "$driver" "$size" "$MEASURE_S" "$WARMUP_S" $extra
      ;;
    attached-idle)
      start_capture "$leg" "api-returns" "json"
      CAP=$CAP_PID
      sampler "$CAP" "$OUT/legs/$leg-sampler.log" &
      SAMPLER=$!
      if ! wait_attach "$OUT/legs/$leg-capture.stderr.log" \
          "$OUT/legs/$leg-attach.txt"; then
        kill "$CAP" 2>/dev/null
        echo "FAIL=attach" > "$OUT/done.txt"
        exit 2
      fi
      sleep $((WARMUP_S + MEASURE_S))
      wait "$CAP"
      echo "capture_rc=$?" > "$OUT/legs/$leg-capture-rc.txt"
      wait "$SAMPLER" 2>/dev/null
      ;;
    aggregation|full-details)
      if [ "$mode" = "aggregation" ]; then
        prof="api-returns"
        fmt="json"
      else
        prof="request-lifecycle"
        fmt="jsonl"
      fi
      start_capture "$leg" "$prof" "$fmt"
      CAP=$CAP_PID
      sampler "$CAP" "$OUT/legs/$leg-sampler.log" &
      SAMPLER=$!
      if ! wait_attach "$OUT/legs/$leg-capture.stderr.log" \
          "$OUT/legs/$leg-attach.txt"; then
        kill "$CAP" 2>/dev/null
        echo "FAIL=attach" > "$OUT/done.txt"
        exit 2
      fi
      # shellcheck disable=SC2086
      run_driver "$leg" "$driver" "$size" "$MEASURE_S" "$WARMUP_S" $extra
      wait "$CAP"
      echo "capture_rc=$?" > "$OUT/legs/$leg-capture-rc.txt"
      wait "$SAMPLER" 2>/dev/null
      ;;
    *)
      echo "unknown mode $mode" > "$OUT/legs/$leg-error.txt"
      FAIL=1
      ;;
  esac
  echo "leg_end=$(date +%s)" >> "$OUT/legs/$leg-wall.txt"
  LEG_DONE=$((LEG_DONE + 1))
  sleep "$SETTLE_S"
done < "$OUT/legs.tsv"
echo "legs_done=$LEG_DONE" > "$OUT/legs-done.txt"

if [ "$NEED_MODULE" = "1" ]; then
  rmmod kcrypto_fixture >> "$OUT/insmod.log" 2>&1
  echo "rmmod_rc=$?" >> "$OUT/insmod-rc.txt"
fi
lsmod | grep -c kcrypto_fixture > "$OUT/lsmod-after.txt" 2>&1 \
  || echo 0 > "$OUT/lsmod-after.txt"
dmesg | grep -E "kcrypto_fixture|kxcipher|kryprobe|Oops" | tail -20 \
  > "$OUT/dmesg-tail.txt" 2>&1
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
if [ "$NEED_MODULE" = "1" ]; then
  if [ "$(cat "$OUT/lsmod-after.txt")" = "0" ] \
      && [ ! -e "$FIX/control" ]; then
    echo "module=1" > "$OUT/cleanup.txt"
  else
    echo "module=0" > "$OUT/cleanup.txt"
  fi
else
  echo "module=n/a" > "$OUT/cleanup.txt"
fi
echo "step=done" > "$OUT/done.txt"
exit "$FAIL"
