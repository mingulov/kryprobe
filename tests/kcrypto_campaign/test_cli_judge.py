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


class ParseRcTests(unittest.TestCase):
    def test_key_value_form(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "refusal-rc.txt").write_text("refusal_rc=4\n")
            self.assertEqual(CLI.parse_rc(cell, "refusal-rc.txt"), 4)

    def test_bare_form(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "refusal-rc.txt").write_text("4\n")
            self.assertEqual(CLI.parse_rc(cell, "refusal-rc.txt"), 4)

    def test_garbage_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "refusal-rc.txt").write_text("nope\n")
            with self.assertRaises(ValueError):
                CLI.parse_rc(cell, "refusal-rc.txt")


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


class ExpectedFilesProducibleTests(unittest.TestCase):
    """Every EXPECTED_FILES entry must be producible by its scenario.

    Regression test for the R02 stale-name bug (the custody gate
    demanded ``capture-write.stderr.log`` while the scenario only
    ever wrote ``capture-product-write.stderr.log``, failing the
    terminal-flush gate on a healthy cell). An expected file is
    producible when it appears literally in the scenario text, is
    a ``capture <name>`` output (``<name>.json`` /
    ``capture-<name>.stderr.log`` via the shared helper), or
    matches a ``$leg`` template instantiated by ``run_leg``
    invocations (r01_det.sh per-leg files).
    """

    def test_expected_files_producible(self):
        import re
        scenarios = ROOT / "scripts" / "kcrypto_campaign" / "scenarios"
        for name, expected in CLI.EXPECTED_FILES.items():
            text = (scenarios / name).read_text()
            captured = set(re.findall(r"^capture (\S+)", text, re.M))
            legs = set(re.findall(r"^run_leg (\S+)", text, re.M))
            templates = set(re.findall(
                r"\$OUT/([A-Za-z0-9_.$-]*\$leg[A-Za-z0-9_.$-]*)", text))
            expanded = {t.replace("$leg", leg)
                        for t in templates for leg in legs}
            for want in expected:
                if want in text or want in expanded:
                    continue
                stem = want.removesuffix(".json")
                cap = want.removeprefix("capture-").removesuffix(
                    ".stderr.log")
                produced = (want.endswith(".json") and stem in captured) or (
                    want.startswith("capture-")
                    and want.endswith(".stderr.log") and cap in captured)
                self.assertTrue(
                    produced,
                    f"{name}: expected file {want!r} is never produced "
                    f"(captures: {sorted(captured)})")


class StimulusIdenticalTests(unittest.TestCase):
    def _cell(self, tmp, ft, prod):
        cell = Path(tmp)
        (cell / "ft.json").write_text(ft)
        (cell / "p.json").write_text(prod)
        return cell

    def test_identical_passes(self):
        import tempfile
        body = '{"write_sha256": "aa", "bytes_written": 64}'
        with tempfile.TemporaryDirectory() as tmp:
            cell = self._cell(tmp, body, body)
            self.assertTrue(CLI.stimulus_identical(
                cell, "ft.json", "p.json", "write_sha256", "bytes_written"))

    def test_sha_mismatch_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = self._cell(
                tmp,
                '{"write_sha256": "aa", "bytes_written": 64}',
                '{"write_sha256": "bb", "bytes_written": 64}')
            self.assertFalse(CLI.stimulus_identical(
                cell, "ft.json", "p.json", "write_sha256", "bytes_written"))

    def test_bytes_mismatch_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = self._cell(
                tmp,
                '{"write_sha256": "aa", "bytes_written": 64}',
                '{"write_sha256": "aa", "bytes_written": 32}')
            self.assertFalse(CLI.stimulus_identical(
                cell, "ft.json", "p.json", "write_sha256", "bytes_written"))

    def test_missing_file_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "ft.json").write_text(
                '{"write_sha256": "aa", "bytes_written": 64}')
            self.assertFalse(CLI.stimulus_identical(
                cell, "ft.json", "p.json", "write_sha256", "bytes_written"))


if __name__ == "__main__":
    unittest.main()
