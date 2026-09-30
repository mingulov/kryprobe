#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the deterministic initramfs writer (attempt 4).

The guest initramfs must be byte-reproducible from frozen inputs:
same inputs, same bytes, every time (fixed uid/gid/mtime, sorted
entries, gzip mtime=0). A naive cpio packing would embed build
timestamps and host ownership, breaking the freeze.
"""

import hashlib
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import cpio  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CpioTests(unittest.TestCase):
    def test_build_is_deterministic(self):
        entries = [
            cpio.file_entry("init", b"#!/bin/sh\necho hi\n", mode=0o755),
            cpio.dir_entry("proc"),
            cpio.symlink_entry("bin/sh", "busybox"),
            cpio.file_entry("bin/busybox", b"\x7fELF-fake", mode=0o755),
        ]
        first = cpio.build_cpio_gz(entries)
        second = cpio.build_cpio_gz(list(reversed(entries)))
        self.assertEqual(digest(first), digest(second))

    def test_entry_order_normalized(self):
        entries = [
            cpio.file_entry("b", b"2", mode=0o644),
            cpio.file_entry("a", b"1", mode=0o644),
        ]
        blob = cpio.build_cpio(entries)
        self.assertLess(blob.index(b"a\x00"), blob.index(b"b\x00"))

    def test_trailer_present(self):
        blob = cpio.build_cpio([cpio.dir_entry("x")])
        self.assertIn(b"TRAILER!!!", blob)

    def test_duplicate_path_refused(self):
        entries = [
            cpio.file_entry("a", b"1", mode=0o644),
            cpio.file_entry("a", b"2", mode=0o644),
        ]
        with self.assertRaises(cpio.CpioError):
            cpio.build_cpio(entries)

    def test_absolute_path_refused(self):
        with self.assertRaises(cpio.CpioError):
            cpio.file_entry("/abs", b"x", mode=0o644)

    def test_parent_escape_refused(self):
        with self.assertRaises(cpio.CpioError):
            cpio.file_entry("a/../../x", b"x", mode=0o644)

    def test_gzip_has_zero_mtime(self):
        blob = cpio.build_cpio_gz([cpio.dir_entry("x")])
        self.assertEqual(blob[0:2], b"\x1f\x8b")
        self.assertEqual(blob[4:8], b"\x00\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
