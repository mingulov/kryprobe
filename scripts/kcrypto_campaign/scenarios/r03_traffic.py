#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T13 R03 XFRM traffic driver (runs in the guest as root).

Sends/receives sequence-numbered UDP packets inside one owned
netns and writes an exact send/receive ledger. The caller runs
one receiver per direction first, then the senders.

Usage:
  r03_traffic.py recv <bind-ip> <port> <count> <out.json> [timeout-s]
  r03_traffic.py send <dst-ip> <port> <count> <payload-bytes> <out.json>

Receiver exits 0 with the ledger written (missing/duplicate
sequence lists are the verdict inputs, never hidden). Sender
paces at ~1000 pps with per-packet sequence numbers and writes
its exact sent count (no sender ledger = unproved direction).
"""

import json
import socket
import struct
import sys
import time

PACING_S = 0.001


def cmd_recv(bind_ip: str, port: int, count: int, out_path: str,
             timeout_s: float = 60.0) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    sock.bind((bind_ip, port))
    sock.settimeout(timeout_s)
    received: list[int] = []
    try:
        while len(received) < count:
            data, _addr = sock.recvfrom(65536)
            (seq,) = struct.unpack("!I", data[:4])
            received.append(seq)
    except socket.timeout:
        pass
    missing = sorted(set(range(count)) - set(received))
    duplicates = sorted(seq for seq in set(received) if received.count(seq) > 1)
    with open(out_path, "w") as fh:
        json.dump({"sent": count, "received": len(received),
                   "missing": missing[:16], "missing_total": len(missing),
                   "duplicates": duplicates[:16],
                   "duplicates_total": len(duplicates)}, fh)
    print(f"recv: {len(received)}/{count} missing={len(missing)} dup={len(duplicates)}")
    return 0


def cmd_send(dst_ip: str, port: int, count: int, payload_bytes: int,
             out_path: str) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    body = b"x" * max(0, payload_bytes - 4)
    sent = 0
    for seq in range(count):
        sock.sendto(struct.pack("!I", seq) + body, (dst_ip, port))
        sent += 1
        time.sleep(PACING_S)
    with open(out_path, "w") as fh:
        json.dump({"sent": sent}, fh)
    print(f"sent: {sent}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: r03_traffic.py recv|send ...", file=sys.stderr)
        return 2
    if argv[1] == "recv" and len(argv) in (6, 7):
        timeout = float(argv[6]) if len(argv) == 7 else 60.0
        return cmd_recv(argv[2], int(argv[3]), int(argv[4]), argv[5], timeout)
    if argv[1] == "send" and len(argv) == 7:
        return cmd_send(argv[2], int(argv[3]), int(argv[4]), int(argv[5]), argv[6])
    print("usage: r03_traffic.py recv|send ...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
