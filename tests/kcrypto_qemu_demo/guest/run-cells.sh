#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Demo guest cell dispatcher (attempt 4).
# Usage: run-cells.sh <CELL-ID>  (exec'd by /init as PID 1)
# No secret material (keys, IVs, tags, payloads, kernel addresses)
# may ever appear on argv, trace output, or console: metadata only.
# Never set -x in this file: the dm-crypt table carries key bytes.
set -eu

CELL="${1:?usage: run-cells.sh <CELL-ID>}"
CONSOLE=/dev/console
OUT=/run/demo
KRYPROBE=/opt/kryprobe/bin/kryprobe

uptime_s() { cut -d' ' -f1 /proc/uptime; }
mark() { echo "DEMO:MARK {\"name\": \"$1\", \"ts_mono\": $(uptime_s)}" > "$CONSOLE"; }
die() { mark "FAILED-$1"; poweroff -f; sleep 30; exit 1; }

# --- shared prelude -------------------------------------------------
# Manifest check, module loads, registry + CPU + device probes.
# Required modules per cell family abort the cell when missing;
# optional ones (aesni on a no-AES CPU) are recorded honestly.
prelude() {
  need="$1"  # space-separated required modules, or "none"
  mark "INIT-READY"
  if ( cd / && sha256sum -c /etc/demo/SHA256SUMS > /dev/null 2>&1 ); then
    mark "MANIFEST-OK"
  else
    die "MANIFEST"
  fi
  for mod in af_alg algif_skcipher algif_hash dm-crypt aesni-intel crypto_engine virtio_crypto; do
    if insmod "/lib/modules/7.0.14-070014-generic/$mod.ko" 2>/dev/null; then
      st=0
    else
      st=$?
    fi
    echo "DEMO:PROBE {\"fact\": \"module\", \"module\": \"$mod\", \"status\": $st}" > "$CONSOLE"
    case " $need " in
      *" $mod "*)
        if [ "$st" -ne 0 ]; then die "MODULE-$mod"; fi
        ;;
    esac
  done
  algd registry > "$CONSOLE"
  mark "REGISTRY-DUMPED"
  flags="$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2)"
  echo "DEMO:CPU {\"flags\": \"$flags\"}" > "$CONSOLE"
  for blk in /sys/block/*; do
    b="${blk##*/}"
    size="$(cat "$blk/size" 2>/dev/null || echo -1)"
    echo "DEMO:PROBE {\"fact\": \"block\", \"dev\": \"$b\", \"sectors\": $size}" > "$CONSOLE"
  done
  if [ -e /sys/kernel/btf/vmlinux ]; then btf=true; else btf=false; fi
  echo "DEMO:PROBE {\"fact\": \"btf\", \"present\": $btf}" > "$CONSOLE"
  for pci in /sys/bus/pci/devices/*; do
    p="${pci##*/}"
    vendor="$(cat "$pci/vendor" 2>/dev/null || echo unknown)"
    device="$(cat "$pci/device" 2>/dev/null || echo unknown)"
    driver="none"
    if [ -e "$pci/driver" ]; then driver="$(basename "$(readlink "$pci/driver")")"; fi
    echo "DEMO:PROBE {\"fact\": \"pci\", \"addr\": \"$p\", \"vendor\": \"$vendor\", \"device\": \"$device\", \"driver\": \"$driver\"}" > "$CONSOLE"
  done
  mark "PRELUDE-DONE"
}

# Highest-priority skcipher driver implementing a generic name.
best_driver() {
  algd registry | grep -F "\"name\": \"$1\"" | grep -F '"type": "skcipher"' \
    | sed -E 's/.*"driver": "([^"]+)".*"priority": ([0-9]+).*/\2 \1/' \
    | sort -rn | head -1 | cut -d' ' -f2
}

# Emit a kryprobe JSON report through the passthrough channel.
passthrough() {
  echo "DEMO:KRYPROBE-BEGIN" > "$CONSOLE"
  cat "$1" > "$CONSOLE"
  echo "DEMO:KRYPROBE-END" > "$CONSOLE"
}

# Resolve a mapped device to its devtmpfs node (/dev/dm-N): no udev
# runs here, so /dev/mapper/<name> never appears; the kernel-owned
# sysfs name is the honest handle.
dm_node() {
  for dm in /sys/block/dm-*; do
    [ -e "$dm/dm/name" ] || continue
    if [ "$(cat "$dm/dm/name")" = "$1" ]; then
      echo "/dev/${dm##*/}"
      return 0
    fi
  done
  return 1
}

finish() {
  mark "WORKLOAD-DONE"
  echo "POWERING-OFF" > "$CONSOLE"
  poweroff -f
  sleep 30
}

# --- PROBE: environment qualification only, no cell verdict --------
cell_PROBE() {
  prelude "none"
  mark "PROBE-KRYPROBE-START"
  if "$KRYPROBE" report --system --duration 10 --format json \
      --out "$OUT/krep-probe.json" > "$OUT/krep-probe.out" 2>&1; then
    echo "DEMO:PROBE {\"fact\": \"kryprobe\", \"exit\": 0}" > "$CONSOLE"
    passthrough "$OUT/krep-probe.json"
  else
    rc=$?
    echo "DEMO:PROBE {\"fact\": \"kryprobe\", \"exit\": $rc}" > "$CONSOLE"
    head -c 2000 "$OUT/krep-probe.out" > "$CONSOLE" 2>/dev/null || true
  fi
  mark "PROBE-LIFECYCLE-START"
  if "$KRYPROBE" report --system --duration 10 --format json \
      --kcrypto-profile request-lifecycle \
      --out "$OUT/krep-probe-lc.json" > "$OUT/krep-probe-lc.out" 2>&1; then
    echo "DEMO:PROBE {\"fact\": \"kryprobe-lifecycle\", \"exit\": 0}" > "$CONSOLE"
  else
    rc=$?
    echo "DEMO:PROBE {\"fact\": \"kryprobe-lifecycle\", \"exit\": $rc}" > "$CONSOLE"
    head -c 2000 "$OUT/krep-probe-lc.out" > "$CONSOLE" 2>/dev/null || true
  fi
  # Root-disk census: partitions + first-level listing, read-only.
  for part in /dev/vda*; do
    [ -e "$part" ] || continue
    echo "DEMO:PROBE {\"fact\": \"rootpart\", \"dev\": \"$part\"}" > "$CONSOLE"
  done
  mkdir -p /sysroot/mnt
  if mount -o ro /dev/vda1 /sysroot/mnt 2>/dev/null; then
    ls /sysroot/mnt > "$OUT/root-top.txt" 2>&1 || true
    echo "DEMO:PROBE {\"fact\": \"rootmount\", \"ok\": true}" > "$CONSOLE"
    if [ -x /sysroot/mnt/sbin/init ]; then has_init=true; else has_init=false; fi
    echo "DEMO:PROBE {\"fact\": \"rootinit\", \"present\": $has_init}" > "$CONSOLE"
    umount /sysroot/mnt || true
  else
    echo "DEMO:PROBE {\"fact\": \"rootmount\", \"ok\": false}" > "$CONSOLE"
  fi
  finish
}

# --- D01: generic + exact-driver allocations, 300 ops total --------
cell_D01() {
  prelude "af_alg algif_skcipher"
  drv="$(best_driver 'cbc(aes)')"
  if [ -z "$drv" ]; then die "NO-CBC-DRIVER"; fi
  echo "DEMO:PROBE {\"fact\": \"selected\", \"name\": \"cbc(aes)\", \"driver\": \"$drv\"}" > "$CONSOLE"
  "$KRYPROBE" report --system --duration 60 --format json \
    --out "$OUT/krep-d01.json" > "$OUT/krep-d01.out" 2>&1 &
  kp=$!
  sleep 2
  mark "WORKLOAD-START"
  algd run --name 'cbc(aes)' --keylen 16 --ops 150 --bytes 4096 \
    --rate 10 --op encrypt --alloc-id d01-generic > "$CONSOLE" || die "ALGD-GENERIC"
  algd run --name "$drv" --keylen 16 --ops 150 --bytes 4096 \
    --rate 10 --op encrypt --alloc-id d01-driver > "$CONSOLE" || die "ALGD-DRIVER"
  mark "WORKLOAD-STOP"
  wait "$kp" || die "KRYPROBE"
  passthrough "$OUT/krep-d01.json"
  finish
}

# --- D02: cpu variant + retained handle across fresh allocs --------
cell_D02() {
  prelude "af_alg algif_skcipher"
  drv="$(best_driver 'cbc(aes)')"
  if [ -z "$drv" ]; then die "NO-CBC-DRIVER"; fi
  echo "DEMO:PROBE {\"fact\": \"selected\", \"name\": \"cbc(aes)\", \"driver\": \"$drv\"}" > "$CONSOLE"
  "$KRYPROBE" report --system --duration 60 --format json \
    --out "$OUT/krep-d02.json" > "$OUT/krep-d02.out" 2>&1 &
  kp=$!
  sleep 2
  mark "WORKLOAD-START"
  algd hold --name 'cbc(aes)' --keylen 16 --hold-s 45 \
    --alloc-id d02-held > "$CONSOLE" &
  held=$!
  sleep 3
  algd run --name 'cbc(aes)' --keylen 16 --ops 150 --bytes 4096 \
    --rate 10 --op encrypt --alloc-id d02-fresh0 > "$CONSOLE" || die "ALGD-FRESH0"
  algd run --name "$drv" --keylen 16 --ops 150 --bytes 4096 \
    --rate 10 --op encrypt --alloc-id d02-fresh1 > "$CONSOLE" || die "ALGD-FRESH1"
  wait "$held" || die "ALGD-HELD"
  mark "WORKLOAD-STOP"
  wait "$kp" || die "KRYPROBE"
  passthrough "$OUT/krep-d02.json"
  finish
}

# --- D03: guest-only dm-crypt, 64 MiB each way + readback ----------
cell_D03() {
  prelude "af_alg algif_skcipher dm-crypt"
  [ -e /dev/vdb ] || die "NO-DATA-DISK"
  sectors="$(cat /sys/block/vdb/size)"
  keyhex="$(od -A n -t x1 -N 64 /dev/urandom | tr -d ' \n')"
  printf '0 %s crypt aes-xts-plain64 %s 0 /dev/vdb 0' "$sectors" "$keyhex" \
    > "$OUT/d03.table"
  chmod 600 "$OUT/d03.table"
  keyhex=""
  "$KRYPROBE" report --system --duration 45 --format json \
    --out "$OUT/krep-d03.json" > "$OUT/krep-d03.out" 2>&1 &
  kp=$!
  sleep 2
  mark "WORKLOAD-START"
  dmap create --name demo-d03 > "$CONSOLE" || die "DMAP-CREATE"
  dmap load --name demo-d03 --table-file "$OUT/d03.table" \
    --sectors "$sectors" > "$CONSOLE" || die "DMAP-LOAD"
  dmap resume --name demo-d03 > "$CONSOLE" || die "DMAP-RESUME"
  dmnode="$(dm_node demo-d03)" || die "NO-DM-NODE"
  echo "DEMO:PROBE {\"fact\": \"dmnode\", \"name\": \"demo-d03\", \"node\": \"$dmnode\"}" > "$CONSOLE"
  iochk --dev "$dmnode" --bytes 67108864 > "$CONSOLE" || die "IOCHK"
  mark "WORKLOAD-STOP"
  dmap remove --name demo-d03 > "$CONSOLE" || die "DMAP-REMOVE"
  wait "$kp" || die "KRYPROBE"
  passthrough "$OUT/krep-d03.json"
  finish
}

# --- D04: one virtual device; claim stops without queue proof ------
cell_D04() {
  prelude "af_alg algif_skcipher virtio_crypto"
  for pci in /sys/bus/pci/devices/*; do
    if [ -e "$pci/driver" ] && \
       [ "$(basename "$(readlink "$pci/driver")")" = "virtio_crypto" ]; then
      echo "DEMO:VIRTIO {\"dev\": \"${pci##*/}\", \"driver\": \"virtio_crypto\", \"queue_proof\": false}" > "$CONSOLE"
    fi
  done
  vdrv="$(algd registry | grep -i 'virtio' | grep -F '"type": "skcipher"' \
    | head -1 | sed -E 's/.*"driver": "([^"]+)".*/\1/')"
  echo "DEMO:PROBE {\"fact\": \"virtio-driver\", \"driver\": \"$vdrv\"}" > "$CONSOLE"
  "$KRYPROBE" report --system --duration 30 --format json \
    --out "$OUT/krep-d04.json" > "$OUT/krep-d04.out" 2>&1 &
  kp=$!
  sleep 2
  mark "WORKLOAD-START"
  if [ -n "$vdrv" ]; then
    if algd run --name "$vdrv" --keylen 16 --ops 50 --bytes 4096 \
        --rate 10 --op encrypt --alloc-id d04-virtio > "$CONSOLE" 2>&1; then
      echo "DEMO:PROBE {\"fact\": \"virtio-alloc\", \"ok\": true}" > "$CONSOLE"
    else
      echo "DEMO:PROBE {\"fact\": \"virtio-alloc\", \"ok\": false}" > "$CONSOLE"
    fi
  else
    echo "DEMO:PROBE {\"fact\": \"virtio-alloc\", \"ok\": false}" > "$CONSOLE"
  fi
  # Generic control on the same boot: selection must not claim offload.
  algd run --name 'cbc(aes)' --keylen 16 --ops 50 --bytes 4096 \
    --rate 10 --op encrypt --alloc-id d04-generic > "$CONSOLE" || die "ALGD-GENERIC"
  mark "WORKLOAD-STOP"
  wait "$kp" || die "KRYPROBE"
  passthrough "$OUT/krep-d04.json"
  finish
}

# --- D05: quiesced removal; guest watches sysfs, host drives QMP ---
cell_D05() {
  prelude "af_alg algif_skcipher virtio_crypto"
  have_before=0
  for pci in /sys/bus/pci/devices/*; do
    if [ -e "$pci/driver" ] && \
       [ "$(basename "$(readlink "$pci/driver")")" = "virtio_crypto" ]; then
      have_before=$((have_before + 1))
      echo "DEMO:VIRTIO {\"dev\": \"${pci##*/}\", \"driver\": \"virtio_crypto\", \"phase\": \"before\"}" > "$CONSOLE"
    fi
  done
  if [ "$have_before" -eq 0 ]; then die "NO-VIRTIO-BEFORE"; fi
  mark "QUIESCED"
  # Wait (bounded) for the host-driven removal to reach sysfs.
  gone=false
  i=0
  while [ "$i" -lt 100 ]; do
    n=0
    for pci in /sys/bus/pci/devices/*; do
      if [ -e "$pci/driver" ] && \
         [ "$(basename "$(readlink "$pci/driver")")" = "virtio_crypto" ]; then
        n=$((n + 1))
      fi
    done
    if [ "$n" -eq 0 ]; then gone=true; break; fi
    sleep 1
    i=$((i + 1))
  done
  if [ "$gone" = true ]; then mark "REMOVAL-OBSERVED"; else die "REMOVAL-NOT-OBSERVED"; fi
  for pci in /sys/bus/pci/devices/*; do
    if [ -e "$pci/driver" ] && \
       [ "$(basename "$(readlink "$pci/driver")")" = "virtio_crypto" ]; then
      echo "DEMO:VIRTIO {\"dev\": \"${pci##*/}\", \"driver\": \"virtio_crypto\", \"phase\": \"after\"}" > "$CONSOLE"
    fi
  done
  # Fresh allocation after removal: reselect or refuse, as observed.
  if algd run --name 'cbc(aes)' --keylen 16 --ops 10 --bytes 4096 \
      --rate 10 --op encrypt --alloc-id d05-fresh > "$CONSOLE" 2>&1; then
    echo "DEMO:PROBE {\"fact\": \"post-removal-alloc\", \"ok\": true}" > "$CONSOLE"
  else
    echo "DEMO:PROBE {\"fact\": \"post-removal-alloc\", \"ok\": false}" > "$CONSOLE"
  fi
  drv2="$(best_driver 'cbc(aes)' || true)"
  echo "DEMO:PROBE {\"fact\": \"selected\", \"name\": \"cbc(aes)\", \"driver\": \"$drv2\"}" > "$CONSOLE"
  finish
}

# --- D07: early observer, attach-ready, then controlled unlock -----
cell_D07() {
  prelude "af_alg algif_skcipher dm-crypt"
  [ -e /dev/vdb ] || die "NO-DATA-DISK"
  if ! "$KRYPROBE" doctor > "$OUT/doctor.txt" 2>&1; then
    die "DOCTOR"
  fi
  "$KRYPROBE" report --system --duration 120 --format json \
    --kcrypto-profile request-lifecycle \
    --out "$OUT/krep-d07.json" > "$OUT/krep-d07.out" 2>&1 &
  kp=$!
  # Attach-ready: the observer holds a live bpf-prog fd (bounded 30 s).
  ready=false
  i=0
  while [ "$i" -lt 30 ]; do
    if ls "/proc/$kp/fdinfo" > /dev/null 2>&1 && \
       grep -l 'prog_id:' "/proc/$kp/fdinfo/"* 2>/dev/null | head -1 | grep -q .; then
      ready=true
      break
    fi
    sleep 1
    i=$((i + 1))
  done
  if [ "$ready" = true ]; then mark "ATTACH-READY"; else die "ATTACH-NOT-READY"; fi
  sectors="$(cat /sys/block/vdb/size)"
  keyhex="$(od -A n -t x1 -N 64 /dev/urandom | tr -d ' \n')"
  printf '0 %s crypt aes-xts-plain64 %s 0 /dev/vdb 0' "$sectors" "$keyhex" \
    > "$OUT/d07.table"
  chmod 600 "$OUT/d07.table"
  keyhex=""
  mark "UNLOCK-START"
  dmap create --name demo-d07 > "$CONSOLE" || die "DMAP-CREATE"
  dmap load --name demo-d07 --table-file "$OUT/d07.table" \
    --sectors "$sectors" > "$CONSOLE" || die "DMAP-LOAD"
  dmap resume --name demo-d07 > "$CONSOLE" || die "DMAP-RESUME"
  mark "UNLOCK-DONE"
  dmnode="$(dm_node demo-d07)" || die "NO-DM-NODE"
  echo "DEMO:PROBE {\"fact\": \"dmnode\", \"name\": \"demo-d07\", \"node\": \"$dmnode\"}" > "$CONSOLE"
  iochk --dev "$dmnode" --bytes 16777216 > "$CONSOLE" || die "IOCHK"
  dmap remove --name demo-d07 > "$CONSOLE" || die "DMAP-REMOVE"
  mark "WORKLOAD-STOP"
  wait "$kp" || die "KRYPROBE"
  passthrough "$OUT/krep-d07.json"
  finish
}

# --- D08: 20-minute bounded aggregate soak + stop under traffic ----
cell_D08() {
  prelude "af_alg algif_skcipher"
  w=0
  while [ "$w" -lt 19 ]; do
    "$KRYPROBE" report --system --duration 60 --format json \
      --out "$OUT/krep-d08-$w.json" > "$OUT/krep-d08-$w.out" 2>&1 &
    kp=$!
    sleep 2
    if algd run --name 'cbc(aes)' --keylen 16 --ops 600 --bytes 4096 \
        --rate 10 --op encrypt --alloc-id "d08-w$w" > "$CONSOLE" 2>&1; then
      ok=true
    else
      ok=false
    fi
    if wait "$kp"; then kexit=0; else kexit=$?; fi
    rows="$(grep -c . "$OUT/krep-d08-$w.json" 2>/dev/null || true)"
    if [ -z "$rows" ]; then rows=0; fi
    echo "DEMO:SOAK {\"window\": $w, \"ops_ok\": $ok, \"kryprobe_exit\": $kexit, \"report_lines\": $rows}" > "$CONSOLE"
    if [ "$ok" != true ] || [ "$kexit" -ne 0 ]; then die "SOAK-W$w"; fi
    w=$((w + 1))
  done
  # Final window: the capture stops while traffic continues.
  "$KRYPROBE" report --system --duration 30 --format json \
    --out "$OUT/krep-d08-stop.json" > "$OUT/krep-d08-stop.out" 2>&1 &
  kp=$!
  sleep 2
  mark "STOP-WINDOW-START"
  algd run --name 'cbc(aes)' --keylen 16 --ops 600 --bytes 4096 \
    --rate 10 --op encrypt --alloc-id d08-stop > "$CONSOLE" || die "SOAK-STOP-OPS"
  if wait "$kp"; then kexit=0; else kexit=$?; fi
  mark "STOP-WINDOW-END"
  rows="$(grep -c . "$OUT/krep-d08-stop.json" 2>/dev/null || true)"
  if [ -z "$rows" ]; then rows=0; fi
  echo "DEMO:SOAK {\"window\": 19, \"ops_ok\": true, \"kryprobe_exit\": $kexit, \"report_lines\": $rows, \"traffic_active_at_stop\": true}" > "$CONSOLE"
  if [ "$kexit" -ne 0 ]; then die "SOAK-STOP-KRYPROBE"; fi
  passthrough "$OUT/krep-d08-stop.json"
  finish
}

case "$CELL" in
  PROBE) cell_PROBE ;;
  D01) cell_D01 ;;
  D02) cell_D02 ;;
  D03) cell_D03 ;;
  D04) cell_D04 ;;
  D05) cell_D05 ;;
  D07) cell_D07 ;;
  D08) cell_D08 ;;
  D06)
    echo "NOT_RUN cell=$CELL reason=x01-threshold-provider-absent" > "$OUT/cell-$CELL.status"
    mark "UNSUPPORTED-X01-ABSENT"
    echo "POWERING-OFF" > "$CONSOLE"
    poweroff -f
    sleep 30
    ;;
  *)
    echo "REFUSED cell=$CELL reason=unknown-cell" > "$OUT/cell-UNKNOWN.status"
    exit 2
    ;;
esac
