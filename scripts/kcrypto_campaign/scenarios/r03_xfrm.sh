#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R03 XFRM guest cell: two owned netns + veth, ESP transport
# SAs (rfc4106(gcm(aes))), 1000 sequence-numbered UDP packets each
# direction with ledgers, then a 100-packet wrong-key auth-fail
# phase; product captures + ftrace AEAD windows throughout; quiet
# windows before/after. SA keys travel in root-only batch files
# (never argv), shredded after; no state dumps archived.
# $1 = staged out dir.
set -u
OUT="$1"
. "$OUT/pins.env"
. "$OUT/ftrace_ref.sh"
export KRYPROBE_BPF_DIR="$OUT/kryprobe-bpf"
KP="$OUT/kryprobe"
NSA=t13a
NSB=t13b
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
  "$KP" report --system --format json --duration "$2" --out "$OUT/$1.json" \
    2> "$OUT/capture-$1.stderr.log" &
  echo $! > "$OUT/$1.pid"
  wait_attach "$OUT/capture-$1.stderr.log" "$OUT/$1-attach.txt" || FAIL=1
}

finish_capture() {
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

modprobe esp4 2>/dev/null
ip netns add "$NSA" 2> "$OUT/netns.log" || FAIL=1
ip netns add "$NSB" 2>> "$OUT/netns.log" || FAIL=1
ip link add v13a type veth peer name v13b 2>> "$OUT/netns.log" || FAIL=1
ip link set v13a netns "$NSA" 2>> "$OUT/netns.log" || FAIL=1
ip link set v13b netns "$NSB" 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSA" addr add 10.13.0.1/24 dev v13a 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSB" addr add 10.13.0.2/24 dev v13b 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSA" link set v13a up 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSB" link set v13b up 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSA" link set lo up 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSB" link set lo up 2>> "$OUT/netns.log" || FAIL=1

# GCM-128 keys: 16-byte key + 4-byte salt per direction (test
# vectors, batch files only, shredded after use).
head -c 16 /dev/urandom > "$OUT/sa-ab.key"
head -c 4 /dev/urandom > "$OUT/sa-ab.salt"
head -c 16 /dev/urandom > "$OUT/sa-ba.key"
head -c 4 /dev/urandom > "$OUT/sa-ba.salt"
chmod 600 "$OUT"/sa-*.key "$OUT"/sa-*.salt
KAB=$(cat "$OUT/sa-ab.key" "$OUT/sa-ab.salt" | od -A n -t x1 | tr -d ' \n')
KBA=$(cat "$OUT/sa-ba.key" "$OUT/sa-ba.salt" | od -A n -t x1 | tr -d ' \n')
{
  echo "state add src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 mode transport enc 'rfc4106(gcm(aes))' 0x$KAB"
  echo "state add src 10.13.0.2 dst 10.13.0.1 proto esp spi 0x1002 mode transport enc 'rfc4106(gcm(aes))' 0x$KBA"
  echo "policy add src 10.13.0.1 dst 10.13.0.2 dir out tmpl src 10.13.0.1 dst 10.13.0.2 proto esp mode transport"
  echo "policy add src 10.13.0.2 dst 10.13.0.1 dir in tmpl src 10.13.0.2 dst 10.13.0.1 proto esp mode transport"
} > "$OUT/batch-a.txt"
{
  echo "state add src 10.13.0.2 dst 10.13.0.1 proto esp spi 0x1002 mode transport enc 'rfc4106(gcm(aes))' 0x$KBA"
  echo "state add src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 mode transport enc 'rfc4106(gcm(aes))' 0x$KAB"
  echo "policy add src 10.13.0.2 dst 10.13.0.1 dir out tmpl src 10.13.0.2 dst 10.13.0.1 proto esp mode transport"
  echo "policy add src 10.13.0.1 dst 10.13.0.2 dir in tmpl src 10.13.0.1 dst 10.13.0.2 proto esp mode transport"
} > "$OUT/batch-b.txt"
chmod 600 "$OUT"/batch-*.txt
ip -n "$NSA" -b "$OUT/batch-a.txt" 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSB" -b "$OUT/batch-b.txt" 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSA" xfrm state 2>/dev/null | grep -c "spi 0x" > "$OUT/xfrm-state-count.txt" 2>&1

FNS="crypto_aead_encrypt crypto_aead_decrypt"

# Quiet-before window.
capture product-quiet-before 8
ftrace_begin "$FNS" || FAIL=1
sleep 3
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-quiet-before.txt" 2>&1 || FAIL=1
finish_capture product-quiet-before

# Main phase: both directions sequentially under one window.
capture product-main 120
ftrace_begin "$FNS" || FAIL=1
ip netns exec "$NSB" python3 "$OUT/r03_traffic.py" recv 10.13.0.2 5001 1000 "$OUT/recv-b.json" \
  > "$OUT/traffic-b.log" 2>&1 &
RECVB=$!
ip netns exec "$NSA" python3 "$OUT/r03_traffic.py" recv 10.13.0.1 5002 1000 "$OUT/recv-a.json" \
  > "$OUT/traffic-a.log" 2>&1 &
RECVB2=$!
sleep 1
ip netns exec "$NSA" python3 "$OUT/r03_traffic.py" send 10.13.0.2 5001 1000 512 "$OUT/sent-a.json" \
  >> "$OUT/traffic-a.log" 2>&1 || FAIL=1
wait "$RECVB"
echo "recvb_rc=$?" > "$OUT/traffic-rc.txt"
ip netns exec "$NSB" python3 "$OUT/r03_traffic.py" send 10.13.0.1 5002 1000 512 "$OUT/sent-b.json" \
  >> "$OUT/traffic-b.log" 2>&1 || FAIL=1
wait "$RECVB2"
echo "recva_rc=$?" >> "$OUT/traffic-rc.txt"
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-main.txt" 2>&1 || FAIL=1
finish_capture product-main

# Auth-fail phase: receiver B's inbound SA gets a wrong key.
head -c 20 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$OUT/sa-wrong.hex"
KW=$(cat "$OUT/sa-wrong.hex")
echo "state update src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 mode transport enc 'rfc4106(gcm(aes))' 0x$KW" \
  > "$OUT/batch-wrong.txt"
chmod 600 "$OUT/batch-wrong.txt"
ip -n "$NSB" -b "$OUT/batch-wrong.txt" 2>> "$OUT/netns.log" || FAIL=1
capture product-authfail 60
ftrace_begin "$FNS" || FAIL=1
ip netns exec "$NSB" python3 "$OUT/r03_traffic.py" recv 10.13.0.2 5003 100 "$OUT/recv-authfail.json" 15 \
  > "$OUT/traffic-authfail.log" 2>&1 &
RECVF=$!
sleep 1
ip netns exec "$NSA" python3 "$OUT/r03_traffic.py" send 10.13.0.2 5003 100 512 "$OUT/sent-authfail.json" \
  >> "$OUT/traffic-authfail.log" 2>&1 || FAIL=1
wait "$RECVF"
echo "recvf_rc=$?" >> "$OUT/traffic-rc.txt"
# shellcheck disable=SC2034
ftrace_end $FNS > "$OUT/kernel-authfail.txt" 2>&1 || FAIL=1
finish_capture product-authfail

# Quiet-after window (namespaces still up, no traffic).
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
           for name in ('quiet-before', 'main', 'authfail', 'quiet-after')}
json.dump({'method': 'trace_stat/functions', 'windows': windows},
          open('$OUT/kernel-ref.json', 'w'), indent=2)
def merge(sent_path, recv_path, out_path):
    sent = json.load(open(sent_path))['sent']
    recv = json.load(open(recv_path))
    recv['sent'] = sent
    json.dump(recv, open(out_path, 'w'), indent=2)
merge('$OUT/sent-a.json', '$OUT/recv-b.json', '$OUT/ledger-a.json')
merge('$OUT/sent-b.json', '$OUT/recv-a.json', '$OUT/ledger-b.json')
merge('$OUT/sent-authfail.json', '$OUT/recv-authfail.json', '$OUT/authfail-ledger.json')
" || FAIL=1

# Cleanup: namespaces (drops veth + SAs + policies), key shredding.
ip netns del "$NSB" 2>> "$OUT/netns.log" || FAIL=1
ip netns del "$NSA" 2>> "$OUT/netns.log" || FAIL=1
shred -u "$OUT"/sa-ab.key "$OUT"/sa-ab.salt "$OUT"/sa-ba.key "$OUT"/sa-ba.salt \
  "$OUT"/batch-a.txt "$OUT"/batch-b.txt "$OUT"/batch-wrong.txt "$OUT"/sa-wrong.hex \
  2>/dev/null || rm -f "$OUT"/sa-*.key "$OUT"/sa-*.salt "$OUT"/batch-*.txt "$OUT"/sa-wrong.hex
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
  if [ -z "$(ip netns list 2>/dev/null)" ]; then echo "namespaces=1"; else echo "namespaces=0"; fi
  if [ -z "$(ip xfrm state 2>/dev/null)" ]; then echo "xfrm=1"; else echo "xfrm=0"; fi
} >> "$OUT/cleanup.txt" 2>&1
echo "step=done" > "$OUT/done.txt"
exit "$FAIL"
