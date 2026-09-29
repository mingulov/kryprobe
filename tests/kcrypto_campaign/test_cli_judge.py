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

    def test_missing_declared_counter_fails(self):
        # P8-N5: the declared counter set is required in EVERY
        # report — a report that omits loss dimensions fails
        # closed instead of passing by silence.
        loss = dict(ZERO_LOSS)
        del loss["ring_drops"]
        self.assertFalse(CLI.transport_closed(parsed_with(loss)))

    def test_missing_integrity_counter_fails(self):
        loss = dict(ZERO_LOSS)
        del loss["budget_omissions"]
        self.assertFalse(CLI.transport_closed(parsed_with(loss)))

    def test_reviewer_erasure_fails(self):
        # P8-N5 exact shape: only ring_drops survives the
        # coverage erasure and every integrity counter is gone.
        self.assertFalse(CLI.transport_closed(
            parsed_with({"ring_drops": "0"})))

    def test_empty_loss_fails(self):
        self.assertFalse(CLI.transport_closed(parsed_with({})))

    def test_missing_in_second_report_fails(self):
        thin = dict(ZERO_LOSS)
        del thin["ktot_gap"]
        self.assertFalse(CLI.transport_closed(
            parsed_with(ZERO_LOSS), parsed_with(thin)))


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

    def test_missing_row_reads_zero(self):
        # Absent row = zero observations (backends omit empty
        # rows); judges fail closed against expected counts.
        self.assertEqual(
            CLI.agg_calls({"agg": {}}, "skcipher", "encrypt"), 0)
        self.assertEqual(
            CLI.agg_bytes({"agg": {}}, "skcipher", "encrypt"), 0)


class ObservedDigestCountsTests(unittest.TestCase):
    def test_sums_full_identity_rows(self):
        # Regression: a short-key lookup silently reads zero for
        # every function; counts must sum across the full
        # (family, op, result, algorithm, driver, context) rows.
        parsed = {"agg": {
            ("ahash", "digest", "ok", "sha256", "d1", "process"):
                {"calls": 7, "bytes": 0},
            ("ahash", "digest", "ok", "sha256", "d2", "process"):
                {"calls": 3, "bytes": 0},
        }}
        observed = CLI.observed_digest_counts(
            parsed, {"crypto_ahash_digest": 10, "crypto_shash_digest": 0})
        self.assertEqual(observed["crypto_ahash_digest"], 10)
        self.assertEqual(observed["crypto_shash_digest"], 0)

    def test_unexpected_function_raises(self):
        with self.assertRaises(CLI.oracles.OracleError):
            CLI.observed_digest_counts(
                {"agg": {}}, {"crypto_skcipher_encrypt": 1})


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


class LedgerTruthTests(unittest.TestCase):
    """P8-N7: fixture truth derived from the sealed ledger rows."""

    LEDGER = (
        '{"v":1,"run":"t","seq":1,"phase":"alloc","req":"r"}\n'
        '{"v":1,"run":"t","seq":1,"phase":"config","op":"setkey","errno":0}\n'
        '{"v":1,"run":"t","seq":2,"phase":"submit","op":"encrypt"}\n'
        '{"v":1,"run":"t","seq":2,"phase":"return","errno":0}\n'
        '{"v":1,"run":"t","seq":2,"phase":"terminal","errno":0}\n'
        '{"v":1,"run":"t","seq":3,"phase":"submit","op":"decrypt"}\n'
        '{"v":1,"run":"t","seq":3,"phase":"return","errno":0}\n'
        '{"v":1,"run":"t","seq":3,"phase":"terminal","errno":0}\n'
        '{"v":1,"run":"t","seq":1,"phase":"free","final":true}\n'
        '{"v":1,"run":"t","phase":"done","fixture_result":0}\n'
    )

    def test_sync_once_truth_counts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            ledger.write_text(self.LEDGER)
            self.assertEqual(
                CLI.ledger_product_truth(ledger),
                {"skcipher/encrypt": 1, "skcipher/decrypt": 1,
                 "any/alloc": 1})

    def test_observed_by_op_sums_families(self):
        parsed = {"agg": {
            ("skcipher", "encrypt", "ok", "k", "d", "process"):
                {"calls": 1, "bytes": 16},
            ("skcipher", "decrypt", "ok", "k", "d", "process"):
                {"calls": 1, "bytes": 16},
            ("any", "alloc", "ok", "r", "", "process"):
                {"calls": 1, "bytes": 0},
        }}
        self.assertEqual(
            CLI.observed_by_op(parsed),
            {"skcipher/encrypt": 1, "skcipher/decrypt": 1,
             "any/alloc": 1})

    def test_observed_by_op_reports_every_family(self):
        # A phantom family appears in the map (so truth equality
        # fails) instead of being silently uncounted.
        parsed = {"agg": {
            ("aead", "encrypt", "ok", "k", "d", "process"):
                {"calls": 2, "bytes": 0},
        }}
        self.assertEqual(CLI.observed_by_op(parsed),
                         {"aead/encrypt": 2})


class SealVerifyTests(unittest.TestCase):
    """P8-N6: the seal is re-derived from cell bytes, never trusted."""

    def _sealed(self, tmp):
        cell = Path(tmp)
        (cell / "a.txt").write_text("hello\n")
        (cell / "sub").mkdir()
        (cell / "sub" / "b.bin").write_bytes(b"\x00\x01")
        CLI.kreceipt.seal_artifacts(
            cell, ["a.txt", "sub/b.bin"], writers_done=True)
        return cell

    def test_intact_seal_passes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ok, _info = CLI.verify_cell_seal(self._sealed(tmp))
            self.assertTrue(ok)

    def test_corrupted_bytes_fail_despite_preserved_seal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = self._sealed(tmp)
            with (cell / "sub" / "b.bin").open("ab") as fh:
                fh.write(b"corruption")
            ok, info = CLI.verify_cell_seal(cell)
            self.assertFalse(ok)
            self.assertIn("sub/b.bin", info["mismatched"])

    def test_missing_seal_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "a.txt").write_text("hello\n")
            ok, _info = CLI.verify_cell_seal(cell)
            self.assertFalse(ok)

    def test_extra_unsealed_file_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = self._sealed(tmp)
            (cell / "evil.txt").write_text("unmanifested\n")
            ok, info = CLI.verify_cell_seal(cell)
            self.assertFalse(ok)
            self.assertIn("evil.txt", info["unmanifested"])


class RederivedIdentityTests(unittest.TestCase):
    """P8-N6: identity stability re-derived from env files."""

    BEFORE = (
        "kernel=7.0.14-070014-generic\n"
        "config_sha=aaa\n"
        "btf_sha=bbb\n"
        "module_sha=none\n"
        "cli_sha=ddd\n"
        "bpf_agg_sha=eee\n"
        "bpf_lc_sha=fff\n"
        "oracle_sha=999\n"
    )

    def _cell(self, tmp, after):
        cell = Path(tmp)
        (cell / "identity-before.env").write_text(self.BEFORE)
        (cell / "identity-after.env").write_text(after)
        return cell

    def test_stable_identity_rederives_true(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            verdict = CLI.rederive_identity(self._cell(tmp, self.BEFORE))
            self.assertTrue(verdict["stable"])

    def test_drifted_post_stop_identity_fails(self):
        import tempfile
        drifted = self.BEFORE.replace(
            "kernel=7.0.14-070014-generic",
            "kernel=6.12.111-0612111-generic")
        with tempfile.TemporaryDirectory() as tmp:
            verdict = CLI.rederive_identity(self._cell(tmp, drifted))
            self.assertFalse(verdict["stable"])
            self.assertIn("kernel", verdict["mismatches"])

    def test_unreadable_identity_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            verdict = CLI.rederive_identity(Path(tmp))
            self.assertFalse(verdict["stable"])


class PinsMatchBytesTests(unittest.TestCase):
    """P8-N6: staged pins must equal the sealed bytes on disk."""

    def test_matching_pins_pass(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "kryprobe").write_bytes(b"binary-bytes")
            pins = {"kryprobe": CLI.sha256_file(cell / "kryprobe"),
                    "kcrypto_fixture.ko": "none"}
            self.assertTrue(CLI.verify_pins_match_bytes(cell, pins))

    def test_resealed_corruption_fails_pins(self):
        # Bytes changed after staging: even a freshly rewritten
        # seal cannot reconcile them with the staged pins.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "kryprobe").write_bytes(b"binary-bytes")
            pins = {"kryprobe": CLI.sha256_file(cell / "kryprobe")}
            (cell / "kryprobe").write_bytes(b"binary-bytes-MUTATED")
            self.assertFalse(CLI.verify_pins_match_bytes(cell, pins))


class DualLockTests(unittest.TestCase):
    """P8-N8: common-plus-task mutual exclusion, proved by receipts."""

    def test_single_lock_refuses(self):
        with self.assertRaisesRegex(ValueError, "two locks"):
            CLI.resolve_lock_paths(["/tmp/only-task.lock"])

    def test_dual_locks_resolve(self):
        paths = CLI.resolve_lock_paths(
            ["/tmp/common.lock", "/tmp/task.lock"])
        self.assertEqual([str(p) for p in paths],
                         ["/tmp/common.lock", "/tmp/task.lock"])

    def _cells(self, tmp, mapping):
        root = Path(tmp)
        for portion, locks in mapping.items():
            cell = root / portion
            cell.mkdir()
            (cell / "spawn.json").write_text(
                __import__("json").dumps({"lock_paths": locks}))
        return root

    def test_common_plus_task_passes(self):
        import tempfile
        mapping = {"R01-det-7014": ["/l/common.lock", "/l/t13.lock"],
                   "R02-7014": ["/l/common.lock", "/l/t13.lock"]}
        with tempfile.TemporaryDirectory() as tmp:
            verdict = CLI.verify_campaign_locks(
                self._cells(tmp, mapping), sorted(mapping))
            self.assertEqual(verdict["verdict"], "PASS")
            self.assertEqual(verdict["common"],
                             ["/l/common.lock", "/l/t13.lock"])

    def test_single_lock_cells_fail(self):
        import tempfile
        mapping = {"R01-det-7014": ["/l/t13.lock"],
                   "R02-7014": ["/l/t13.lock"]}
        with tempfile.TemporaryDirectory() as tmp:
            verdict = CLI.verify_campaign_locks(
                self._cells(tmp, mapping), sorted(mapping))
            self.assertEqual(verdict["verdict"], "FAIL")

    def test_no_common_lock_fails(self):
        import tempfile
        mapping = {"R01-det-7014": ["/l/a.lock", "/l/t13.lock"],
                   "R02-7014": ["/l/b.lock", "/l/t13b.lock"]}
        with tempfile.TemporaryDirectory() as tmp:
            verdict = CLI.verify_campaign_locks(
                self._cells(tmp, mapping), sorted(mapping))
            self.assertEqual(verdict["verdict"], "FAIL")

    def test_missing_spawn_receipt_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "R01-det-7014").mkdir()
            verdict = CLI.verify_campaign_locks(
                root, ["R01-det-7014"])
            self.assertEqual(verdict["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
