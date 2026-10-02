#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the M1 early-gate harness (Task02).

Manifest loading (M1 + frozen dispatch), M1 leg generation
(alternation, per-side modes, expected_alloc threads), ctx telemetry
parsing (fail-closed), per-shape exactness rules, M1 set verdicts
(10/12 qualification, enforced attempt budget, ENVELOPE for
informational sets), M1 driver arg validation + deterministic churn
counts + shard merging, and frozen-harness non-regression. Run from
the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_m1.py'
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_cli",
    str(ROOT / "scripts" / "kcrypto-perf.py"))
CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CLI)

from kcrypto_perf import m1manifest, m1validity  # noqa: E402

_DRIVER_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_m1",
    str(ROOT / "tests" / "fixtures" / "kcrypto_perf_m1.py"))
M1DRIVER = importlib.util.module_from_spec(_DRIVER_SPEC)
_DRIVER_SPEC.loader.exec_module(M1DRIVER)


def write_tmp(content, suffix=""):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return Path(fh.name)


class ManifestTests(unittest.TestCase):
    def test_m1_manifest_loads(self):
        manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")
        self.assertEqual(len(manifest["sets"]), 24)
        self.assertEqual(len(manifest["diagnostics"]), 1)
        self.assertTrue(CLI.is_m1_manifest(manifest))

    def test_dispatch_by_schema(self):
        m1 = CLI.load_any_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")
        self.assertTrue(CLI.is_m1_manifest(m1))
        frozen = CLI.load_any_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells.json")
        self.assertFalse(CLI.is_m1_manifest(frozen))

    def test_mode_obs_mismatch_refused(self):
        manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")
        manifest["sets"][0]["obs_a"] = "D"
        path = write_tmp(json.dumps(
            {k: v for k, v in manifest.items()
             if not k.startswith("_")}))
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(path)

    def test_disabled_side_b_refused(self):
        # F-05: side B must be an observer (the quiet leg runs the
        # side-B binary); flip one set's B side to D/disabled.
        manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")
        manifest["sets"][0]["obs_b"] = "D"
        manifest["sets"][0]["mode_b"] = "disabled"
        path = write_tmp(json.dumps(
            {k: v for k, v in manifest.items()
             if not k.startswith("_")}))
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(path)


class LegGenTests(unittest.TestCase):
    def setUp(self):
        self.manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")

    def test_cr_set_ten_pairs_alternating_both_observed(self):
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        legs = CLI.gen_legs(entry, self.manifest, "set")
        self.assertEqual(len(legs), 20)
        # Pair 0 starts A, pair 1 starts B (frozen alternation).
        self.assertEqual([leg["side"] for leg in legs[:4]],
                         ["A", "B", "B", "A"])
        self.assertTrue(all(leg["mode"] == "aggregation" for leg in legs))
        self.assertTrue(all(leg["threads"] == 1 for leg in legs))

    def test_cd_set_disabled_a(self):
        entry = CLI.find_set(self.manifest, "m1-P-1M-n_cgroup-cd")
        legs = CLI.gen_legs(entry, self.manifest, "set")
        self.assertEqual(len(legs), 20)
        for leg in legs:
            want = "disabled" if leg["side"] == "A" else "aggregation"
            self.assertEqual(leg["mode"], want)
            self.assertEqual(leg["threads"], 64)

    def test_churn_threads_are_deterministic_arrivals(self):
        below = CLI.find_set(self.manifest, "m1-P-4K-churn_below-cr")
        full = CLI.find_set(self.manifest, "m1-P-4K-churn_full-cr")
        legs_below = CLI.gen_legs(below, self.manifest, "set")
        legs_full = CLI.gen_legs(full, self.manifest, "set")
        self.assertTrue(all(leg["threads"] == 200 for leg in legs_below))
        self.assertTrue(all(leg["threads"] == 800 for leg in legs_full))

    def test_spares_continue_numbering(self):
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        legs = CLI.gen_legs(entry, self.manifest, "set",
                            start_pair=10, n_pairs=2)
        self.assertEqual([leg["leg_id"] for leg in legs],
                         ["leg10A", "leg10B", "leg11B", "leg11A"])

    def test_diag_leg(self):
        entry = CLI.find_diag(self.manifest, "m1-diag-612-ctx")
        legs = CLI.gen_legs(entry, self.manifest, "diag")
        self.assertEqual(len(legs), 1)
        self.assertEqual(legs[0]["mode"], "aggregation")
        self.assertEqual(legs[0]["size"], 4096)

    def test_frozen_gen_unchanged(self):
        frozen = CLI.load_any_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells.json")
        entry = CLI.find_set(frozen, "perf-P-4K-agg-7014")
        legs = CLI.gen_legs(entry, frozen, "set")
        self.assertEqual(len(legs), 12)  # 5 pairs + bulk pair
        self.assertEqual(legs[0]["mode"], "disabled")
        self.assertEqual(legs[1]["mode"], "aggregation")


class CtxParseTests(unittest.TestCase):
    PREFIX = "kryprobe: telemetry "

    def _line(self, obj):
        return self.PREFIX + json.dumps(obj) + "\n"

    def test_happy_path_last_wins(self):
        content = (self._line({"v": 1, "tick": 1, "lagmax_us": 5})
                   + self._line({"v": 1, "ctx": {"rows": 1,
                                                 "present_calls": 1,
                                                 "system_calls": 1,
                                                 "unknown_calls": 0,
                                                 "drops": 0}})
                   + self._line({"v": 1, "ctx": {"rows": 3,
                                                 "present_calls": 100,
                                                 "system_calls": 100,
                                                 "unknown_calls": 0,
                                                 "drops": 0}}))
        ctx = m1validity.parse_ctx_telemetry(write_tmp(content))
        self.assertEqual(ctx["rows"], 3)
        self.assertEqual(ctx["present_calls"], 100)

    def test_missing_raises(self):
        content = self._line({"v": 1, "tick": 1, "lagmax_us": 5})
        with self.assertRaises(ValueError):
            m1validity.parse_ctx_telemetry(write_tmp(content))

    def test_mistyped_and_bool_rejected(self):
        for bad in ({"rows": 1.5}, {"rows": True}, {"drops": "0"}):
            good = {"rows": 3, "present_calls": 100, "system_calls": 100,
                    "unknown_calls": 0, "drops": 0}
            good.update(bad)
            with self.assertRaises(ValueError, msg=bad):
                m1validity.parse_ctx_telemetry(
                    write_tmp(self._line({"v": 1, "ctx": good})))

    def test_nulls_allowed(self):
        good = {"rows": None, "present_calls": None, "system_calls": None,
                "unknown_calls": None, "drops": None}
        ctx = m1validity.parse_ctx_telemetry(
            write_tmp(self._line({"v": 1, "ctx": good})))
        self.assertIsNone(ctx["rows"])


class CtxRuleTests(unittest.TestCase):
    def test_below_capacity_exact(self):
        ctx = {"rows": 192, "present_calls": 5000, "system_calls": 5000,
               "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 5000, 5000, "n_cgroup", 192), [])

    def test_below_capacity_violations(self):
        base = {"rows": 3, "present_calls": 100, "system_calls": 100,
                "unknown_calls": 0, "drops": 0}
        cases = [
            ({"present_calls": 99, "unknown_calls": 1}, "present"),
            ({"unknown_calls": 1, "system_calls": 101}, "unknown"),
            ({"drops": 1}, "drops"),
            ({"rows": 4}, "rows"),
        ]
        for delta, needle in cases:
            ctx = dict(base)
            ctx.update(delta)
            # Keep the identity consistent except for the targeted rule
            # (system/present/unknown must still add up unless the
            # contradiction itself is under test).
            reasons = m1validity.check_ctx_leg(ctx, ctx["system_calls"],
                                              100, "single", 3)
            self.assertTrue(any(needle in reason for reason in reasons),
                            f"{delta} -> {reasons}")

    def test_contradiction_distinct_from_unreadable(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": None, "drops": 0}
        reasons = m1validity.check_ctx_leg(ctx, 100, 100, "single", 3)
        self.assertTrue(any("contradiction" in reason for reason in reasons))

    def test_system_must_match_report_totals(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        reasons = m1validity.check_ctx_leg(ctx, 999, 100, "single", 3)
        self.assertTrue(any("report totals" in reason for reason in reasons))

    def test_churn_full_rules(self):
        ctx = {"rows": 1024, "present_calls": 9000, "system_calls": 10000,
               "unknown_calls": 1000, "drops": 1000}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 10000, 10000, "churn_full", 1024),
            [])
        bad_rows = dict(ctx, rows=1023)
        self.assertTrue(m1validity.check_ctx_leg(
            bad_rows, 10000, 10000, "churn_full", 1024))
        bad_silent = dict(ctx, unknown_calls=0, drops=0,
                          present_calls=10000)
        self.assertTrue(m1validity.check_ctx_leg(
            bad_silent, 10000, 10000, "churn_full", 1024))

    def test_expected_rows_none_skips_pin(self):
        ctx = {"rows": 7, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 100, 100, "single", None), [])


class SetVerdictTests(unittest.TestCase):
    def setUp(self):
        self.manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")

    def _pairs(self, n, inside=True, seed=0):
        pairs = []
        for i in range(n):
            if inside:
                ratio_t, ratio_p = 0.99, 1.02
            else:
                ratio_t, ratio_p = (0.90, 1.20) if (i + seed) % 2 == 0 \
                    else (0.91, 1.21)
            pairs.append({"pair": f"leg{i:02d}", "valid": True,
                          "reasons": [],
                          "ratios": {"throughput": ratio_t, "p99": ratio_p}})
        return pairs

    def _cells(self, pairs):
        # judge_m1_set only reads verdict errors + form_pairs over
        # legs; bypass form_pairs by patching pair lists directly via
        # a minimal cell list is not possible, so drive the real path:
        # build one fake cell verdict per real form_pairs input is
        # heavy; instead call the verdict core through judge_m1_set
        # with pre-formed pairs by monkeypatching form_pairs.
        return [{"cell": "fake", "errors": []}]

    def test_pass_fail_inconclusive(self):
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        real_form = CLI.form_pairs
        try:
            CLI.form_pairs = lambda cells: self._pairs(10, inside=True)
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "PASS")
            CLI.form_pairs = lambda cells: self._pairs(10, inside=False)
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "FAIL")
            mixed = self._pairs(5, inside=True) + \
                self._pairs(5, inside=False, seed=1)
            CLI.form_pairs = lambda cells: mixed
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "INCONCLUSIVE")
        finally:
            CLI.form_pairs = real_form

    def test_qualification_and_attempt_budget(self):
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        real_form = CLI.form_pairs
        try:
            CLI.form_pairs = lambda cells: self._pairs(9, inside=True)
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "INVALID")
            CLI.form_pairs = lambda cells: self._pairs(13, inside=True)
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "INVALID")
            self.assertTrue(any("budget" in reason
                                for reason in judged["reasons"]))
        finally:
            CLI.form_pairs = real_form

    def test_informational_is_envelope(self):
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cd")
        real_form = CLI.form_pairs
        try:
            CLI.form_pairs = lambda cells: self._pairs(10, inside=True)
            judged = CLI.judge_m1_set("m1-P-4K-single-cd", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "ENVELOPE")
            self.assertIn("throughput", judged["medians"])
        finally:
            CLI.form_pairs = real_form


class DriverTests(unittest.TestCase):
    def test_churn_counts_deterministic(self):
        self.assertEqual(
            M1DRIVER._churn_arrival_count({"warm": 10.0, "meas": 30.0,
                                           "churn_every_ms": 200}), 200)
        self.assertEqual(
            M1DRIVER._churn_arrival_count({"warm": 10.0, "meas": 30.0,
                                           "churn_every_ms": 50}), 800)

    def test_arg_validation(self):
        good = ["m1", "skcipher", "4096", "30", "10", "--actors", "64",
                "--cgroups", "16", "ledger.csv"]
        self.assertIsNotNone(M1DRIVER.parse_args(good))
        good_churn = ["m1", "skcipher", "4096", "30", "10",
                      "--churn-every-ms", "200", "--churn-ops", "8",
                      "ledger.csv"]
        self.assertIsNotNone(M1DRIVER.parse_args(good_churn))
        bad_cases = [
            ["m1", "skcipher", "4096", "30", "10", "--actors", "3",
             "--cgroups", "2", "ledger.csv"],
            ["m1", "skcipher", "4096", "30", "10", "--churn-every-ms",
             "200", "ledger.csv"],
            ["m1", "skcipher", "4096", "30", "10", "--actors", "4",
             "--cgroups", "2", "--churn-every-ms", "200",
             "--churn-ops", "8", "ledger.csv"],
            ["m1", "skcipher", "4096", "30", "10", "--actors", "4",
             "--cgroups", "2", "--bulk", "ledger.csv"],
            ["m1", "async", "16", "30", "10", "--actors", "4",
             "--cgroups", "4", "ledger.csv"],
        ]
        for argv in bad_cases:
            self.assertIsNone(M1DRIVER.parse_args(argv), argv)

    def test_merge_rewrites_seqs_pairing_intact(self):
        tmp = Path(tempfile.mkdtemp())
        for shard_id, n in (("a", 3), ("b", 2)):
            with open(tmp / f"s{shard_id}", "w") as fh:
                fh.write("seq,phase,op,dt_ns\n")
                for seq in range(n):
                    fh.write(f"{seq},meas,encrypt,100\n")
                    fh.write(f"{seq},meas,decrypt,200\n")
            summary = {"ops_total": n, "ops_meas": n, "rows_meas": 2 * n,
                       "fails": 0, "late": 0, "offered": n,
                       "t_warm_start_ns": 1000,
                       "t_meas_start_ns": 2500 if shard_id == "b" else 2000}
            with open(tmp / f"s{shard_id}.summary.json", "w") as fh:
                json.dump(summary, fh)
        merged = M1DRIVER._merge_shards(
            [str(tmp / "sa"), str(tmp / "sb")], str(tmp / "merged.csv"))
        self.assertEqual(merged[:3], (5, 5, 10))
        rows = (tmp / "merged.csv").read_text().splitlines()[1:]
        seqs = sorted(int(line.split(",")[0]) for line in rows)
        # Globally unique seqs 0..4, each exactly twice (enc+dec).
        self.assertEqual(seqs, [0, 0, 1, 1, 2, 2, 3, 3, 4, 4])


if __name__ == "__main__":
    unittest.main()
