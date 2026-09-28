#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the campaign CLI judge helpers.

Imports ``scripts/kcrypto-campaign.py`` by path (stdlib only, no
guests). Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_cli_judge.py'
"""

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_campaign_cli", str(ROOT / "scripts" / "kcrypto-campaign.py"))
CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CLI)


def parsed_with(loss):
    return {"loss": dict(loss)}


ZERO_LOSS = {name: "0" for name in CLI.KNOWN_ZERO}


class TransportClosedTests(unittest.TestCase):
    def test_all_zero_passes(self):
        self.assertTrue(CLI.transport_closed(parsed_with(ZERO_LOSS)))

    def test_recorded_markers_ignored(self):
        loss = dict(ZERO_LOSS)
        loss["uncovered:kernel_delivery_unmeasured"] = "1"
        loss["predrop_destroy_skip"] = "2"
        self.assertTrue(CLI.transport_closed(parsed_with(loss)))

    def test_ring_drop_fails(self):
        loss = dict(ZERO_LOSS)
        loss["ring_drops"] = "1"
        self.assertFalse(CLI.transport_closed(parsed_with(loss)))

    def test_ktot_gap_fails(self):
        loss = dict(ZERO_LOSS)
        loss["ktot_gap"] = "3"
        self.assertFalse(CLI.transport_closed(parsed_with(loss)))

    def test_predrop_failure_fails(self):
        loss = dict(ZERO_LOSS)
        loss["predrop_chase_fail"] = "1"
        self.assertFalse(CLI.transport_closed(parsed_with(loss)))

    def test_unknown_nonzero_counter_fails(self):
        loss = dict(ZERO_LOSS)
        loss["some_new_counter"] = "1"
        self.assertFalse(CLI.transport_closed(parsed_with(loss)))

    def test_unknown_zero_counter_passes(self):
        loss = dict(ZERO_LOSS)
        loss["some_new_counter"] = "0"
        self.assertTrue(CLI.transport_closed(parsed_with(loss)))

    def test_second_report_loss_fails(self):
        self.assertFalse(CLI.transport_closed(
            parsed_with(ZERO_LOSS),
            parsed_with({**ZERO_LOSS, "budget_omissions": "1"})))


class AggSummingTests(unittest.TestCase):
    def test_sums_across_algorithms(self):
        parsed = {"agg": {
            ("skcipher", "encrypt", "ok", "cbc(aes)", "", "process"):
                {"calls": 1, "bytes": 64},
            ("skcipher", "encrypt", "ok", "__cbc(aes)", "", "process"):
                {"calls": 1, "bytes": 64},
        }}
        self.assertEqual(CLI.agg_calls(parsed, "skcipher", "encrypt"), 2)
        self.assertEqual(CLI.agg_bytes(parsed, "skcipher", "encrypt"), 128)

    def test_missing_row_raises(self):
        with self.assertRaisesRegex(CLI.oracles.OracleError, "no agg row"):
            CLI.agg_calls({"agg": {}}, "skcipher", "encrypt")


class FixtureStdoutTests(unittest.TestCase):
    def test_hash_markers(self):
        text = "hash: 20 digests done\ngenerator finished\n"
        self.assertTrue(CLI.parse_fixture_stdout(text, "hash", 20))
        self.assertFalse(CLI.parse_fixture_stdout(text, "hash", 19))

    def test_skcipher_markers(self):
        text = "skcipher: 20 ops done\ngenerator finished\n"
        self.assertTrue(CLI.parse_fixture_stdout(text, "skcipher", 10))
        self.assertFalse(CLI.parse_fixture_stdout("skcipher: 20 ops done\n",
                                                  "skcipher", 10))

    def test_missing_trailer_fails(self):
        self.assertFalse(CLI.parse_fixture_stdout("hash: 20 digests done\n",
                                                  "hash", 20))


class GuestStageMatchTests(unittest.TestCase):
    def test_match_passes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "environment.txt").write_text(
                "ko=aaa\nobj_agg=bbb\nobj_lc=ccc\nkryprobe=ddd\n")
            receipt = {"pins": {"kcrypto_fixture.ko": "aaa",
                                "kryprobe-bpf/kcrypto.bpf.o": "bbb",
                                "kryprobe-bpf/kcrypto-lifecycle.bpf.o": "ccc",
                                "kryprobe": "ddd"}}
            self.assertTrue(CLI.guest_matches_stage(cell, receipt))

    def test_mismatch_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "environment.txt").write_text(
                "ko=zzz\nobj_agg=bbb\nobj_lc=ccc\nkryprobe=ddd\n")
            receipt = {"pins": {"kcrypto_fixture.ko": "aaa",
                                "kryprobe-bpf/kcrypto.bpf.o": "bbb",
                                "kryprobe-bpf/kcrypto-lifecycle.bpf.o": "ccc",
                                "kryprobe": "ddd"}}
            self.assertFalse(CLI.guest_matches_stage(cell, receipt))

    def test_missing_environment_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(CLI.guest_matches_stage(Path(tmp), {"pins": {}}))


if __name__ == "__main__":
    unittest.main()
