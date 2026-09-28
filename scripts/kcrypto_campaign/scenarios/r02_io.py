#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T13 R02 dm-crypt workload driver (runs in the guest as root).

Writes (O_DIRECT)/reads (buffered) a fixed 64 MiB pattern in
4 KiB blocks on the owned dm-crypt mapping with pacing (bounded
IOPS so the observer never bursts), fsyncs, and compares
in-memory checksums. Writes are O_DIRECT so every 4 KiB block
completes its dm-crypt encrypt synchronously, mirroring the
synchronous read leg: buffered writes defer all encrypts to
background writeback plus one fsync burst, a concentration the
observer demonstrably short-counts (R02-7014 attempts 2-3).

Usage:
  r02_io.py write /dev/mapper/<name> <out.json>
  r02_io.py read /dev/mapper/<name> <out.json> <expected-sha256>
  r02_io.py wrongkey-read /dev/mapper/<name> <expected-sha256>
    (exits 0 with MISMATCH printed iff the checksum differs)

Writes one JSON leg file per invocation; the caller merges legs
into workload.json. Never prints key material (there is none
here: the mapping key lives only in the setup step).
"""

import ctypes
import hashlib
import json
import mmap
import os
import sys
import time

TOTAL_BYTES = 64 * 1024 * 1024
BLOCK = 4096
# Pacing: ~250 blocks/s per leg (~65 s per 64 MiB leg),
# keeping instantaneous kworker concurrency low (T12
# precedent: paced proof). Buffered writes additionally
# defer all encrypts to one fsync burst, which the observer
# short-counts (R02-7014 attempts 2-3); hence O_DIRECT
# writes with synchronous per-block completion.
BLOCKS_PER_BURST = 50
BURST_SLEEP_S = 0.2


def pattern(length: int) -> bytes:
    return bytes((i % 251 for i in range(length)))


def aligned_block() -> mmap.mmap:
    """One page-aligned 4 KiB buffer for O_DIRECT writes."""
    buf = mmap.mmap(-1, BLOCK)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
    if addr % BLOCK != 0:
        raise RuntimeError(f"O_DIRECT buffer misaligned: {addr:#x}")
    return buf


def cmd_write(dev: str, out_path: str) -> int:
    data = pattern(TOTAL_BYTES)
    digest = hashlib.sha256(data).hexdigest()
    written = 0
    burst = 0
    buf = aligned_block()
    fd = os.open(dev, os.O_WRONLY | os.O_DIRECT)
    try:
        for offset in range(0, TOTAL_BYTES, BLOCK):
            buf.seek(0)
            buf.write(data[offset:offset + BLOCK])
            buf.seek(0)
            # A short O_DIRECT write would leave a torn block
            # (unaligned resume); fail closed instead.
            done = os.write(fd, buf)
            if done != BLOCK:
                print(f"short O_DIRECT write: {done} at {offset}",
                      file=sys.stderr)
                return 1
            written += BLOCK
            burst += 1
            if burst >= BLOCKS_PER_BURST:
                time.sleep(BURST_SLEEP_S)
                burst = 0
        os.fsync(fd)
    finally:
        os.close(fd)
    with open(out_path, "w") as fh:
        json.dump({"bytes_written": written, "write_sha256": digest}, fh)
    print(f"write: {written} bytes sha={digest[:16]}...")
    return 0


def cmd_read(dev: str, out_path: str, expected: str) -> int:
    seen = hashlib.sha256()
    read = 0
    burst = 0
    # A block device has no EOF at our 64 MiB: stop after exactly
    # TOTAL_BYTES (reading the whole mapping would decrypt 1 GiB).
    with open(dev, "rb") as fh:
        while read < TOTAL_BYTES:
            chunk = fh.read(min(BLOCK, TOTAL_BYTES - read))
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
    read = 0
    with open(dev, "rb") as fh:
        while read < TOTAL_BYTES:
            chunk = fh.read(min(65536, TOTAL_BYTES - read))
            if not chunk:
                break
            seen.update(chunk)
            read += len(chunk)
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
