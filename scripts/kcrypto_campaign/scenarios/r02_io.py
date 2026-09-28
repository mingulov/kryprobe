#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T13 R02 dm-crypt workload driver (runs in the guest as root).

Writes/reads a fixed 64 MiB pattern in 4 KiB blocks on the owned
dm-crypt mapping with pacing (bounded IOPS so the observer ring
never bursts), fsyncs, and compares in-memory checksums.

Usage:
  r02_io.py write /dev/mapper/<name> <out.json>
  r02_io.py read /dev/mapper/<name> <out.json> <expected-sha256>
  r02_io.py wrongkey-read /dev/mapper/<name> <expected-sha256>
    (exits 0 with MISMATCH printed iff the checksum differs)

Writes one JSON leg file per invocation; the caller merges legs
into workload.json. Never prints key material (there is none
here: the mapping key lives only in the setup step).
"""

import hashlib
import json
import os
import sys
import time

TOTAL_BYTES = 64 * 1024 * 1024
BLOCK = 4096
# Pacing: at most ~1000 blocks/s per leg (16 s per 64 MiB leg).
BLOCKS_PER_BURST = 100
BURST_SLEEP_S = 0.1


def pattern(length: int) -> bytes:
    return bytes((i % 251 for i in range(length)))


def cmd_write(dev: str, out_path: str) -> int:
    data = pattern(TOTAL_BYTES)
    digest = hashlib.sha256(data).hexdigest()
    written = 0
    burst = 0
    with open(dev, "wb") as fh:
        for offset in range(0, TOTAL_BYTES, BLOCK):
            fh.write(data[offset:offset + BLOCK])
            written += BLOCK
            burst += 1
            if burst >= BLOCKS_PER_BURST:
                fh.flush()
                time.sleep(BURST_SLEEP_S)
                burst = 0
        fh.flush()
        os.fsync(fh.fileno())
    with open(out_path, "w") as fh:
        json.dump({"bytes_written": written, "write_sha256": digest}, fh)
    print(f"write: {written} bytes sha={digest[:16]}...")
    return 0


def cmd_read(dev: str, out_path: str, expected: str) -> int:
    seen = hashlib.sha256()
    read = 0
    burst = 0
    with open(dev, "rb") as fh:
        while True:
            chunk = fh.read(BLOCK)
            if not chunk:
                break
            seen.update(chunk)
            read += len(chunk)
            burst += 1
            if burst >= BLOCKS_PER_BURST:
                time.sleep(BURST_SLEEP_S)
                burst = 0
    digest = seen.hexdigest()
    match = digest == expected
    with open(out_path, "w") as fh:
        json.dump({"bytes_read": read, "read_sha256": digest,
                   "checksums_match": match}, fh)
    print(f"read: {read} bytes match={match}")
    return 0 if match else 1


def cmd_wrongkey_read(dev: str, expected: str) -> int:
    seen = hashlib.sha256()
    with open(dev, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            seen.update(chunk)
    mismatch = seen.hexdigest() != expected
    print("MISMATCH" if mismatch else "UNEXPECTED-MATCH")
    return 0 if mismatch else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: r02_io.py write|read|wrongkey-read ...", file=sys.stderr)
        return 2
    if argv[1] == "write" and len(argv) == 4:
        return cmd_write(argv[2], argv[3])
    if argv[1] == "read" and len(argv) == 5:
        return cmd_read(argv[2], argv[3], argv[4])
    if argv[1] == "wrongkey-read" and len(argv) == 4:
        return cmd_wrongkey_read(argv[2], argv[3])
    print("usage: r02_io.py write|read|wrongkey-read ...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
