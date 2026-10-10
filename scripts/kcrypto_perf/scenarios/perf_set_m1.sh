#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# M1 early-gate pair-set guest cell: one boot runs a quiet leg plus the
# staged legs.tsv rows (leg_id, side, mode, cls, driver, size,
# workload, paced, bulk, threads). TWO observer artifacts (obs-A/ and
# obs-B/, each exe + sibling kryprobe-bpf/ — the elevated exe-dir tier
# is what loads; the env tier is refused when elevated per H-SEC-01):
# side A legs use obs-A, side B legs use obs-B, so C/R pairs alternate
# artifacts within one boot. DISABLED sides carry a DISABLED marker
# instead of a binary (mode=disabled legs never touch it). Modes:
# disabled (driver only) and aggregation (api-returns capture); M1
# runs no full-details legs. $M1_DRIVER_FLAGS (from set.env, staged
# from the manifest) carries the workload shape flags (--actors/
# --cgroups/--churn-*); the legs.tsv `threads` column is the judge's
# expected_alloc and is NEVER passed to the M1 driver (its --threads
# stays 1; actor shape comes from M1_DRIVER_FLAGS). $1 = staged out dir.
# Exit 0: all legs attempted; exit 2: set abort (ambient traffic,
# attach timeout, warmup failure, or module failure) — host seals
# partial, verify marks the set INVALID (never retried into green).
#
# Task05 Stage 4 (freeze G3/G6): M sides (role M in set.env OBS_A/B)
# run the metadata configuration: --format workload-json
# --workload-metadata <staged file>, report to
# legs/LEG-report.workload-json, plus a sealed per-leg legs/LEG-m.json
# audit (metadata/helper shas + principal). M captures run as the
# unprivileged bench user via setpriv (exec semantics: $! stays the
# observer pid for the sampler/wait/kill paths — runuser would fork
# and break all three); root has no trustworthy principal (typed
# no_principal, helper never launches), so an M leg as root is not
# an M leg. `token mint` grants the staged M binaries their file
# caps in-guest (xattr-only: content hashes are unaffected). Any
# M-preflight failure aborts the boot (FAIL=m-preflight, exit 2) —
# never a silent root fallback (that would un-freeze the M meaning).
set -u
OUT="$1"
. "$OUT/pins.env"
. "$OUT/set.env"
D="$OUT/kcrypto_perf.py"
FIX=/sys/kernel/debug/kcrypto_fixture
FAIL=0
M_USER="none"
M_UID=""
M_GID=""
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

# M-preflight (freeze G3): with an M side staged, establish the
# unprivileged bench principal, prove the staged M bytes (helper
# present + executable, metadata sha == staged pin), and grant the
# staged M binaries their file caps. Any failure aborts the boot
# (the M legs cannot run their frozen shape — loud, never a
# silent downgrade to a root/no_principal leg).
if [ "$OBS_A" = "M" ] || [ "$OBS_B" = "M" ]; then
  M_USER="bench"
  M_FAIL=""
  command -v setpriv >/dev/null 2>&1 || M_FAIL=1
  if ! id -u bench >/dev/null 2>&1; then
    useradd -M -s /usr/sbin/nologin bench >/dev/null 2>&1 || M_FAIL=1
  fi
  for side in A B; do
    case "$side" in
      A) OBS="$OBS_A" ;;
      B) OBS="$OBS_B" ;;
    esac
    if [ "$OBS" = "M" ]; then
      [ -x "$OUT/obs-$side/kryprobe-workload-helper" ] || M_FAIL=1
      if [ "$(sha256sum "$OUT/obs-$side/workload-metadata.json" \
          2>/dev/null | cut -d' ' -f1)" != "$METADATA_SHA" ]; then
        M_FAIL=1
      fi
      "$OUT/obs-$side/kryprobe" token mint \
        --bin "$OUT/obs-$side/kryprobe" \
        >"$OUT/m-mint-$side.log" 2>&1 || M_FAIL=1
      "$OUT/obs-$side/kryprobe" token status \
        --bin "$OUT/obs-$side/kryprobe" \
        >>"$OUT/m-mint-$side.log" 2>&1 || M_FAIL=1
    fi
  done
  if [ -n "$M_FAIL" ]; then
    echo "FAIL=m-preflight" > "$OUT/done.txt"
    exit 2
  fi
  chown bench "$OUT/legs" || {
    echo "FAIL=m-preflight" > "$OUT/done.txt"
    exit 2
  }
  M_UID=$(id -u bench)
  M_GID=$(id -g bench)
fi

{
  echo "kernel=$(uname -r)"
  echo "uid=$(id -u)"
  echo "head=$(cat "$OUT/head-sha.txt")"
  echo "nproc=$(nproc)"
  echo "mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  echo "ko=$(sha256sum "$OUT/kcrypto_fixture.ko" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_a_kryprobe=$(sha256sum "$OUT/obs-A/kryprobe" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_a_agg=$(sha256sum "$OUT/obs-A/kryprobe-bpf/kcrypto.bpf.o" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_a_lc=$(sha256sum "$OUT/obs-A/kryprobe-bpf/kcrypto-lifecycle.bpf.o" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_a_metadata=$(sha256sum "$OUT/obs-A/workload-metadata.json" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_a_helper=$(sha256sum "$OUT/obs-A/kryprobe-workload-helper" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_b_kryprobe=$(sha256sum "$OUT/obs-B/kryprobe" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_b_agg=$(sha256sum "$OUT/obs-B/kryprobe-bpf/kcrypto.bpf.o" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_b_lc=$(sha256sum "$OUT/obs-B/kryprobe-bpf/kcrypto-lifecycle.bpf.o" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_b_metadata=$(sha256sum "$OUT/obs-B/workload-metadata.json" 2>/dev/null | cut -d' ' -f1)"
  echo "obs_b_helper=$(sha256sum "$OUT/obs-B/kryprobe-workload-helper" 2>/dev/null | cut -d' ' -f1)"
  echo "m_user=$M_USER"
  echo "driver=$(sha256sum "$D" | cut -d' ' -f1)"
  echo "driver_flags=$M1_DRIVER_FLAGS"
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
  echo "cli_a_sha=$CLI_A_SHA"
  echo "bpf_a_agg_sha=$BPF_A_AGG_SHA"
  echo "bpf_a_lc_sha=$BPF_A_LC_SHA"
  echo "cli_b_sha=$CLI_B_SHA"
  echo "bpf_b_agg_sha=$BPF_B_AGG_SHA"
  echo "bpf_b_lc_sha=$BPF_B_LC_SHA"
  echo "metadata_sha=$METADATA_SHA"
  echo "helper_a_sha=$HELPER_A_SHA"
  echo "helper_b_sha=$HELPER_B_SHA"
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
  # $1 = leg id, $2 = profile, $3 = format, $4 = side (A/B),
  # $5 = observer role (R/C/M/D). Sets $CAP_PID in the MAIN shell
  # (never via $(...) — a substitution would hold the stdout pipe
  # open and block until the capture ends, running the driver after
  # the window instead of inside it). The observer binary + sibling
  # kryprobe-bpf/ come from obs-$side (exe-dir tier loads when
  # elevated; the env tier is refused). M legs run the staged CLI
  # as bench via setpriv (exec: $! stays the observer pid) with
  # --format workload-json --workload-metadata <staged file>;
  # anything but the api-returns profile refuses (the argument
  # layer refuses workload views on request-lifecycle).
  leg="$1"
  profile_args=""
  if [ "$2" = "request-lifecycle" ]; then
    profile_args="--kcrypto-profile request-lifecycle"
  fi
  if [ "$5" = "M" ] && [ "$2" != "api-returns" ]; then
    echo "M observer needs the api-returns profile" \
      > "$OUT/legs/$leg-error.txt"
    echo "FAIL=m-shape" > "$OUT/done.txt"
    exit 2
  fi
  KP="$OUT/obs-$4/kryprobe"
  export KRYPROBE_BPF_DIR="$OUT/obs-$4/kryprobe-bpf"
  if [ "$5" = "M" ]; then
    # shellcheck disable=SC2086
    setpriv --reuid="$M_UID" --regid="$M_GID" --clear-groups \
      "$KP" report --system $profile_args --duration "$CAPTURE_S" \
      --format workload-json \
      --workload-metadata "$OUT/obs-$4/workload-metadata.json" \
      --out "$OUT/legs/$leg-report.workload-json" \
      > "$OUT/legs/$leg-capture.stdout.log" \
      2> "$OUT/legs/$leg-capture.stderr.log" &
    CAP_PID=$!
  else
    # shellcheck disable=SC2086
    "$KP" report --system $profile_args --duration "$CAPTURE_S" \
      --format "$3" --out "$OUT/legs/$leg-report.$3" \
      > "$OUT/legs/$leg-capture.stdout.log" \
      2> "$OUT/legs/$leg-capture.stderr.log" &
    CAP_PID=$!
  fi
}

write_m_json() {
  # $1 = leg id, $2 = side (A/B). Sealed per-leg M-active audit
  # (freeze G6): the exact frozen bytes this leg ran with plus the
  # unprivileged principal. The judge verifies both shas against
  # the staged pins and refuses a root principal.
  m_meta=$(sha256sum "$OUT/obs-$2/workload-metadata.json" \
    | cut -d' ' -f1)
  m_help=$(sha256sum "$OUT/obs-$2/kryprobe-workload-helper" \
    | cut -d' ' -f1)
  printf '%s\n' "{" \
    "  \"schema\": \"kryprobe-m1-mleg/v1\"," \
    "  \"leg_id\": \"$1\"," \
    "  \"side\": \"$2\"," \
    "  \"obs\": \"M\"," \
    "  \"metadata_sha256\": \"$m_meta\"," \
    "  \"helper_sha256\": \"$m_help\"," \
    "  \"principal_uid\": $M_UID" \
    "}" > "$OUT/legs/$1-m.json"
}

# Pre-quiet crypto warmup (F2 + A3): first-use kernel autoloads (alg
# templates, request_module workers) fire crypto kevents on their
# first request — inside the quiet window or the first leg they read
# as ambient/pollution (canary leg00A). One tiny driver run through
# the REAL leg path BEFORE quiet absorbs every first-use load (same
# cipher the legs use, so the same module set); request_module is
# synchronous, so the boot is quiescent when the warmup exits. No
# observer runs during warmup (nothing to pollute); the throwaway
# warmup-* files are sealed with the cell for audit and ignored by
# the judge (it iterates staged legs.tsv rows, not files). Warmup
# failure aborts the boot (the legs would fail the same way — loud,
# never retried into green).
run_driver "warmup" "skcipher" "4096" "1" "1"
if ! grep -q "^driver_rc=0$" "$OUT/legs/warmup-driver-rc.txt" 2>/dev/null \
  || ! grep -q "^driver_timeout=0$" "$OUT/legs/warmup-driver-rc.txt" \
  2>/dev/null; then
  echo "FAIL=warmup" > "$OUT/done.txt"
  exit 2
fi

# Quiet leg: any ambient crypto traffic aborts the boot (fast fail —
# a polluted boot cannot yield equivalent-work pairs). Runs the side-B
# observer binary (side B is always an observer — C, R, or M — never
# DISABLED; the manifest loader refuses obs_b=D); side-A attach is
# proven on its own first observed leg via wait_attach below. M sets
# run the exact M leg configuration minus workload (freeze §4
# default): ambient traffic AND M-shape failures (metadata/helper/
# principal) abort the boot loudly before any leg burns time.
echo "quiet_start=$(date +%s)" > "$OUT/quiet-wall.txt"
export KRYPROBE_BPF_DIR="$OUT/obs-B/kryprobe-bpf"
if [ "$OBS_B" = "M" ]; then
  setpriv --reuid="$M_UID" --regid="$M_GID" --clear-groups \
    "$OUT/obs-B/kryprobe" report --system --format workload-json \
    --workload-metadata "$OUT/obs-B/workload-metadata.json" \
    --duration "$QUIET_S" \
    --out "$OUT/legs/quiet-report.workload-json" \
    2> "$OUT/quiet-capture.stderr.log" &
  QCAP=$!
  wait_attach "$OUT/quiet-capture.stderr.log" "$OUT/quiet-attach.txt" || FAIL=1
  wait "$QCAP"
  echo "capture_rc=$?" > "$OUT/quiet-rc.txt"
  mv "$OUT/legs/quiet-report.workload-json" \
    "$OUT/quiet-report.workload-json"
else
  "$OUT/obs-B/kryprobe" report --system --format json --duration "$QUIET_S" \
    --out "$OUT/quiet-report.json" 2> "$OUT/quiet-capture.stderr.log" &
  QCAP=$!
  wait_attach "$OUT/quiet-capture.stderr.log" "$OUT/quiet-attach.txt" || FAIL=1
  wait "$QCAP"
  echo "capture_rc=$?" > "$OUT/quiet-rc.txt"
fi
echo "quiet_end=$(date +%s)" >> "$OUT/quiet-wall.txt"
if [ "$OBS_B" = "M" ]; then
QUIET_CALLS=$(python3 -c "
import json
d = json.load(open('$OUT/quiet-report.workload-json'))
print(d['ledger']['system_total'])
" 2>/dev/null || echo "PARSE_FAIL")
else
QUIET_CALLS=$(python3 -c "
import json
d = json.load(open('$OUT/quiet-report.json'))
for o in d['observations']:
    p = o['backend_payload']
    if p.get('row') == 'totals':
        print(p['counts']['calls'])
" 2>/dev/null || echo "PARSE_FAIL")
fi
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
  # M1: NEVER --threads (the column is the judge's expected_alloc;
  # actor shape comes from the manifest via M1_DRIVER_FLAGS).
  # shellcheck disable=SC2086
  extra="$extra $M1_DRIVER_FLAGS"
  case "$side" in A) OBS="$OBS_A";; B) OBS="$OBS_B";; esac
  case "$mode" in
    disabled)
      # shellcheck disable=SC2086
      run_driver "$leg" "$driver" "$size" "$MEASURE_S" "$WARMUP_S" $extra
      ;;
    attached-idle)
      start_capture "$leg" "api-returns" "json" "$side" "$OBS"
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
      start_capture "$leg" "$prof" "$fmt" "$side" "$OBS"
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
      if [ "$OBS" = "M" ]; then
        write_m_json "$leg" "$side"
      fi
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
  echo "cli_a_sha=$CLI_A_SHA"
  echo "bpf_a_agg_sha=$BPF_A_AGG_SHA"
  echo "bpf_a_lc_sha=$BPF_A_LC_SHA"
  echo "cli_b_sha=$CLI_B_SHA"
  echo "bpf_b_agg_sha=$BPF_B_AGG_SHA"
  echo "bpf_b_lc_sha=$BPF_B_LC_SHA"
  echo "metadata_sha=$METADATA_SHA"
  echo "helper_a_sha=$HELPER_A_SHA"
  echo "helper_b_sha=$HELPER_B_SHA"
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
