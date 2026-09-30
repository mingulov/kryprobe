#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for strict guest-console parsing (attempt 4, RED-first).

Standard library only; no guests, no privilege, no qemu. The guest
speaks to the host only through serial-console marker lines
(``DEMO:<channel> <json>``); ``console.py`` turns them into sealed
ledgers. A naive parser would mislabel noise, accept gapped
sequences, or pass secret material through — every test below pins
a fail-closed behavior:

- unknown channels and malformed JSON refuse (never silently skip);
- ledger sequences must be gapless from 0 (a gap is lost evidence);
- denylisted secret-ish JSON keys refuse anywhere in a DEMO line;
- kernel noise is ignored but counted (provenance, not confusion);
- multi-line product-report passthrough reassembles exactly.
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import console  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_ledger_lines_parse(self):
        text = (
            "[    0.123] some kernel noise\n"
            'DEMO:LEDGER {"seq": 0, "op": "encrypt", "bytes": 4096,'
            ' "status": 0, "alloc_id": "a0", "ts_mono": 1.5}\n'
            'DEMO:LEDGER {"seq": 1, "op": "encrypt", "bytes": 4096,'
            ' "status": 0, "alloc_id": "a0", "ts_mono": 1.6}\n'
            'DEMO:MARK {"name": "WORKLOAD-DONE", "ts_mono": 2.0}\n'
        )
        parsed = console.parse_console(text)
        self.assertEqual(len(parsed["LEDGER"]), 2)
        self.assertEqual(parsed["LEDGER"][0]["seq"], 0)
        self.assertEqual(parsed["MARK"][0]["name"], "WORKLOAD-DONE")
        self.assertGreaterEqual(parsed["noise_lines"], 1)

    def test_unknown_channel_refused(self):
        with self.assertRaises(console.ConsoleError):
            console.parse_console('DEMO:FROBNICATE {"a": 1}\n')

    def test_malformed_json_refused(self):
        with self.assertRaises(console.ConsoleError):
            console.parse_console("DEMO:LEDGER {not json}\n")

    def test_malformed_prefix_refused(self):
        with self.assertRaises(console.ConsoleError):
            console.parse_console("DEMOLEDGER {}\n")

    def test_secret_field_refused(self):
        for field in ("key", "iv", "tag", "payload", "plaintext",
                      "ciphertext", "aad", "kaddr"):
            with self.subTest(field=field):
                line = f'DEMO:LEDGER {{"seq": 0, "{field}": "deadbeef"}}\n'
                with self.assertRaises(console.ConsoleError):
                    console.parse_console(line)

    def test_kernel_noise_ignored_but_counted(self):
        text = "[ 0.1] a\n[ 0.2] b\n"
        parsed = console.parse_console(text)
        self.assertEqual(parsed["noise_lines"], 2)
        self.assertEqual(parsed["LEDGER"], [])

    def test_kryprobe_passthrough_reassembled(self):
        text = (
            "DEMO:KRYPROBE-BEGIN\n"
            '{"session": "s1",\n'
            ' "rows": [{"api": "skcipher_encrypt", "count": 3}]}\n'
            "DEMO:KRYPROBE-END\n"
        )
        parsed = console.parse_console(text)
        self.assertEqual(parsed["KRYPROBE"]["session"], "s1")
        self.assertEqual(
            parsed["KRYPROBE"]["rows"], [{"api": "skcipher_encrypt", "count": 3}]
        )

    def test_kryprobe_passthrough_exempt_from_denylist(self):
        # Product-owned bytes ride unscanned (fixed v0 schema from
        # the pinned renderer); guest DEMO channels stay scanned.
        text = (
            "DEMO:KRYPROBE-BEGIN\n"
            '{"buckets": [{"key": "skcipher_encrypt", "count": 3}]}\n'
            "DEMO:KRYPROBE-END\n"
        )
        parsed = console.parse_console(text)
        self.assertEqual(
            parsed["KRYPROBE"]["buckets"],
            [{"key": "skcipher_encrypt", "count": 3}],
        )

    def test_unterminated_passthrough_refused(self):
        with self.assertRaises(console.ConsoleError):
            console.parse_console("DEMO:KRYPROBE-BEGIN\n{\"a\": 1}\n")

    def test_nested_passthrough_refused(self):
        text = "DEMO:KRYPROBE-BEGIN\nDEMO:KRYPROBE-BEGIN\nDEMO:KRYPROBE-END\n"
        with self.assertRaises(console.ConsoleError):
            console.parse_console(text)


class SequenceTests(unittest.TestCase):
    def test_gapless_sequence_ok(self):
        rows = [{"seq": 0}, {"seq": 1}, {"seq": 2}]
        self.assertEqual(console.check_sequence(rows), {"count": 3})

    def test_ledger_sequence_gap_fails(self):
        rows = [{"seq": 0}, {"seq": 2}]
        with self.assertRaises(console.ConsoleError):
            console.check_sequence(rows)

    def test_sequence_must_start_at_zero(self):
        with self.assertRaises(console.ConsoleError):
            console.check_sequence([{"seq": 1}])

    def test_duplicate_seq_fails(self):
        with self.assertRaises(console.ConsoleError):
            console.check_sequence([{"seq": 0}, {"seq": 0}])

    def test_empty_sequence_fails(self):
        with self.assertRaises(console.ConsoleError):
            console.check_sequence([])


class MarkTests(unittest.TestCase):
    def test_marks_ordered(self):
        marks = [
            {"name": "INIT-READY", "ts_mono": 1.0},
            {"name": "WORKLOAD-DONE", "ts_mono": 2.0},
        ]
        self.assertTrue(console.marks_ordered(marks, ["INIT-READY", "WORKLOAD-DONE"]))

    def test_marks_out_of_order_fail(self):
        marks = [
            {"name": "WORKLOAD-DONE", "ts_mono": 2.0},
            {"name": "INIT-READY", "ts_mono": 1.0},
        ]
        self.assertFalse(
            console.marks_ordered(marks, ["INIT-READY", "WORKLOAD-DONE"])
        )

    def test_missing_mark_fails(self):
        marks = [{"name": "INIT-READY", "ts_mono": 1.0}]
        self.assertFalse(
            console.marks_ordered(marks, ["INIT-READY", "WORKLOAD-DONE"])
        )


if __name__ == "__main__":
    unittest.main()
