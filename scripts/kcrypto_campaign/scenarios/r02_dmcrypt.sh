#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R02 dm-crypt guest cell: owned 1 GiB sparse file -> loop ->
# aes-xts-plain64 mapping; 64 MiB in 4 KiB blocks each direction
# with checksums under product captures + ftrace windows; quiet
# windows before/after; wrong-key leg on the same owned mapping.
# No key material in argv, traces or receipts (key file only,
# shredded; tables redacted). $1 = staged out dir.
set -u
OUT="$1"
. "$OUT/pins.env"
. "$OUT/ftrace_ref.sh"
export KRYPROBE_BPF_DIR="$OUT/kryprobe-bpf"
KP="$OUT/kryprobe"
MAP=t13r02
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

capture() {
  # $1=name $2=duration
  "$KP" report --system --format json --duration "$2" --out "$OUT/$1.json" \
    2> "$OUT/capture-$1.stderr.log" &
  echo $! > "$OUT/$1.pid"
  wait_attach "$OUT/capture-$1.stderr.log" "$OUT/$1-attach.txt" || FAIL=1
}

finish_capture() {
  # $1=name
  wait "$(cat "$OUT/$1.pid")"
  rc=$?
  echo "capture_rc=$rc" > "$OUT/$1-rc.txt"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then FAIL=1; fi
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

modprobe dm_crypt 2>/dev/null
modprobe dm_mod 2>/dev/null
dd if=/dev/zero of="$OUT/backing.img" bs=1M count=1024 status=none || FAIL=1
LOOP=$(losetup -f --show "$OUT/backing.img" 2> "$OUT/loop.log") || FAIL=1
echo "loop=$LOOP" >> "$OUT/loop.log"
head -c 64 /dev/urandom > "$OUT/map.key"
chmod 600 "$OUT/map.key"
KEY=$(od -A n -t x1 "$OUT/map.key" | tr -d ' \n')
SECTORS=$((1024 * 1024 * 1024 / 512))
echo "0 $SECTORS crypt aes-xts-plain64 $KEY 0 $LOOP 0" | dmsetup create "$MAP" \
  2>> "$OUT/loop.log" || FAIL=1
dmsetup table "$MAP" 2>/dev/null | sed -E 's/ [0-9a-f]{64,} / <key-redacted> /' \
  > "$OUT/dm-table.txt" 2>&1
dmsetup status "$MAP" > "$OUT/dm-status.txt" 2>&1

FNS="crypto_skcipher_encrypt crypto_skcipher_decrypt"

# Quiet-before window.
capture product-quiet-before 8
ftrace_begin "$FNS" || FAIL=1
sleep 3
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-quiet-before.txt" 2>&1 || FAIL=1
finish_capture product-quiet-before

# Write leg.
capture product-write 120
ftrace_begin "$FNS" || FAIL=1
python3 "$OUT/r02_io.py" write "/dev/mapper/$MAP" "$OUT/leg-write.json" \
  > "$OUT/io-write.log" 2>&1 || FAIL=1
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-write.txt" 2>&1 || FAIL=1
finish_capture product-write
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

# Read leg.
capture product-read 120
ftrace_begin "$FNS" || FAIL=1
WRITE_SHA=$(python3 -c "import json; print(json.load(open('$OUT/leg-write.json'))['write_sha256'])")
python3 "$OUT/r02_io.py" read "/dev/mapper/$MAP" "$OUT/leg-read.json" "$WRITE_SHA" \
  > "$OUT/io-read.log" 2>&1 || FAIL=1
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-read.txt" 2>&1 || FAIL=1
finish_capture product-read

# Wrong-key leg on the same owned mapping (expect checksum mismatch).
dmsetup remove "$MAP" 2>> "$OUT/loop.log" || FAIL=1
shred -u "$OUT/map.key" 2>/dev/null || rm -f "$OUT/map.key"
head -c 64 /dev/urandom > "$OUT/map.key"
chmod 600 "$OUT/map.key"
KEY2=$(od -A n -t x1 "$OUT/map.key" | tr -d ' \n')
echo "0 $SECTORS crypt aes-xts-plain64 $KEY2 0 $LOOP 0" | dmsetup create "$MAP" \
  2>> "$OUT/loop.log" || FAIL=1
python3 "$OUT/r02_io.py" wrongkey-read "/dev/mapper/$MAP" "$WRITE_SHA" \
  > "$OUT/io-wrongkey.log" 2>&1
echo "wrongkey_rc=$?" > "$OUT/io-wrongkey-rc.txt"
dmsetup remove "$MAP" 2>> "$OUT/loop.log" || FAIL=1

# Quiet-after window (mapping gone: residual crypto must be zero).
capture product-quiet-after 8
ftrace_begin "$FNS" || FAIL=1
sleep 3
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-quiet-after.txt" 2>&1 || FAIL=1
finish_capture product-quiet-after

python3 -c "
import json
def counts(path):
    out = {}
    for line in open(path):
        name, _, value = line.partition(' ')
        out[name.strip()] = int(value.strip())
    return out
windows = {name: counts('$OUT/kernel-%s.txt' % name)
           for name in ('quiet-before', 'write', 'read', 'quiet-after')}
json.dump({'method': 'trace_stat/functions', 'windows': windows},
          open('$OUT/kernel-ref.json', 'w'), indent=2)
write = json.load(open('$OUT/leg-write.json'))
read = json.load(open('$OUT/leg-read.json'))
wrongkey = open('$OUT/io-wrongkey.log').read().strip() == 'MISMATCH'
json.dump({'bytes_written': write['bytes_written'],
           'bytes_read': read['bytes_read'],
           'checksums_match': read['checksums_match'],
           'wrongkey_checksum_mismatch': wrongkey},
          open('$OUT/workload.json', 'w'), indent=2)
"

# Cleanup: loop detach + key shred + backing removal.
losetup -d "$LOOP" 2>> "$OUT/loop.log"; echo "undetach_rc=$?" >> "$OUT/loop.log"
shred -u "$OUT/map.key" 2>/dev/null || rm -f "$OUT/map.key"
rm -f "$OUT/backing.img"
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
ftrace_cleanup_marker "$OUT/cleanup.txt"
{
  if dmsetup ls 2>/dev/null | grep -q "$MAP"; then echo "mapping=0"; else echo "mapping=1"; fi
  if losetup -a 2>/dev/null | grep -q backing.img; then echo "loop=0"; else echo "loop=1"; fi
  if [ -e "$OUT/map.key" ]; then echo "keyfile=0"; else echo "keyfile=1"; fi
} >> "$OUT/cleanup.txt" 2>&1
echo "step=done" > "$OUT/done.txt"
exit "$FAIL"
