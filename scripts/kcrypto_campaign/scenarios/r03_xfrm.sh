#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T13 R03 XFRM guest cell: two owned netns + veth, ESP transport
# SAs (authenc(hmac(sha256),cbc(aes))); rfc4106(gcm(aes)) exists
# in the kernel but this iproute2 refuses to install it, and
# chacha20poly1305.ko loads without registering), 1000
# sequence-numbered UDP packets each direction with ledgers,
# then a 100-packet wrong-auth-key auth-fail phase; product
# captures + ftrace AEAD windows throughout; quiet windows
# before/after. SA keys travel in root-only batch files (never
# argv), shredded after; no state dumps archived.
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

# authenc keys per direction: 16-byte AES-CBC enc key + 32-byte
# HMAC-SHA256 auth key. Batch files only, shredded after use.
head -c 16 /dev/urandom > "$OUT/sa-ab.enc"
head -c 32 /dev/urandom > "$OUT/sa-ab.auth"
head -c 16 /dev/urandom > "$OUT/sa-ba.enc"
head -c 32 /dev/urandom > "$OUT/sa-ba.auth"
chmod 600 "$OUT"/sa-ab.* "$OUT"/sa-ba.*
EAB=$(od -A n -t x1 "$OUT/sa-ab.enc" | tr -d ' \n')
AAB=$(od -A n -t x1 "$OUT/sa-ab.auth" | tr -d ' \n')
EBA=$(od -A n -t x1 "$OUT/sa-ba.enc" | tr -d ' \n')
ABA=$(od -A n -t x1 "$OUT/sa-ba.auth" | tr -d ' \n')
{
  echo "xfrm state add src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 mode transport auth hmac(sha256) 0x$AAB enc cbc(aes) 0x$EAB"
  echo "xfrm state add src 10.13.0.2 dst 10.13.0.1 proto esp spi 0x1002 mode transport auth hmac(sha256) 0x$ABA enc cbc(aes) 0x$EBA"
  echo "xfrm policy add src 10.13.0.1 dst 10.13.0.2 dir out tmpl src 10.13.0.1 dst 10.13.0.2 proto esp mode transport"
  echo "xfrm policy add src 10.13.0.2 dst 10.13.0.1 dir in tmpl src 10.13.0.2 dst 10.13.0.1 proto esp mode transport"
} > "$OUT/batch-a.txt"
{
  echo "xfrm state add src 10.13.0.2 dst 10.13.0.1 proto esp spi 0x1002 mode transport auth hmac(sha256) 0x$ABA enc cbc(aes) 0x$EBA"
  echo "xfrm state add src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 mode transport auth hmac(sha256) 0x$AAB enc cbc(aes) 0x$EAB"
  echo "xfrm policy add src 10.13.0.2 dst 10.13.0.1 dir out tmpl src 10.13.0.2 dst 10.13.0.1 proto esp mode transport"
  echo "xfrm policy add src 10.13.0.1 dst 10.13.0.2 dir in tmpl src 10.13.0.1 dst 10.13.0.2 proto esp mode transport"
} > "$OUT/batch-b.txt"
chmod 600 "$OUT"/batch-*.txt
ip -n "$NSA" -b "$OUT/batch-a.txt" 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSB" -b "$OUT/batch-b.txt" 2>> "$OUT/netns.log" || FAIL=1
ip -n "$NSA" xfrm state 2>/dev/null | grep -c "spi 0x" > "$OUT/xfrm-state-count.txt" 2>&1
# Both SAs must exist in each namespace: a silent half-install
# would run traffic unencrypted past every later gate.
if [ "$(cat "$OUT/xfrm-state-count.txt")" != "2" ]; then FAIL=1; fi
if [ "$(ip -n "$NSB" xfrm state 2>/dev/null | grep -c "spi 0x")" != "2" ]; then FAIL=1; fi

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

# Auth-fail phase: receiver B's inbound SA is deleted and re-added
# with a wrong AUTH key (enc key unchanged): every decrypt runs,
# then HMAC verify fails. Delete+add, not `state update`: update
# returns 0 yet leaves the effective SA unchanged (attempt 5
# delivered 100/100 with all decrypts ok).
head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$OUT/sa-wrong.hex"
KW=$(cat "$OUT/sa-wrong.hex")
EAB2=$(od -A n -t x1 "$OUT/sa-ab.enc" | tr -d ' \n')
ip -n "$NSB" xfrm state delete src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 \
  2>> "$OUT/netns.log" || FAIL=1
echo "xfrm state add src 10.13.0.1 dst 10.13.0.2 proto esp spi 0x1001 mode transport auth hmac(sha256) 0x$KW enc cbc(aes) 0x$EAB2" \
  > "$OUT/batch-wrong.txt"
chmod 600 "$OUT/batch-wrong.txt"
ip -n "$NSB" -b "$OUT/batch-wrong.txt" 2>> "$OUT/netns.log" || FAIL=1
if [ "$(ip -n "$NSB" xfrm state 2>/dev/null | grep -c "spi 0x")" != "2" ]; then FAIL=1; fi
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
shred -u "$OUT"/sa-ab.enc "$OUT"/sa-ab.auth "$OUT"/sa-ba.enc "$OUT"/sa-ba.auth \
  "$OUT"/batch-a.txt "$OUT"/batch-b.txt "$OUT"/batch-wrong.txt "$OUT"/sa-wrong.hex \
  2>/dev/null || rm -f "$OUT"/sa-ab.* "$OUT"/sa-ba.* "$OUT"/batch-*.txt "$OUT"/sa-wrong.hex
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
