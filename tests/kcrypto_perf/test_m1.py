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
import os
import socket
import sys
import tempfile
import time
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

from kcrypto_perf import m1manifest, m1validity, successorvalidity  # noqa: E402

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


def _afalg_usable():
    """Probe AF_ALG cbc(aes) (the M1 driver's cipher): driver live-run
    tests skip loudly without it (capability probe, not a behavior
    skip)."""
    try:
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind(("skcipher", "cbc(aes)"))
        sock.close()
    except OSError:
        return False
    return True


class ManifestTests(unittest.TestCase):
    def test_m1_manifest_loads(self):
        # Task05 Stage 4 (freeze G10): the final 40-set v2 matrix.
        manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")
        self.assertEqual(len(manifest["sets"]), 40)
        self.assertEqual(manifest["manifest_version"], 2)
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


class AttachAuditTests(unittest.TestCase):
    def _line(self, obj):
        return json.dumps(obj) + "\n"

    def test_happy_path_last_wins(self):
        content = (self._line({"audit": "attach", "attached": 8,
                               "expected": 9})
                   + self._line({"audit": "attach", "attached": 9,
                                 "expected": 9}))
        audit = m1validity.parse_attach_audit(write_tmp(content))
        self.assertEqual(audit, {"attached": 9, "expected": 9})

    def test_missing_raises(self):
        content = self._line({"audit": "object-load", "path": "x"})
        with self.assertRaises(ValueError):
            m1validity.parse_attach_audit(write_tmp(content))

    def test_mistyped_and_bool_rejected(self):
        cases = ({"attached": 9.0, "expected": 9},
                 {"attached": True, "expected": 9},
                 {"attached": 9, "expected": "9"},
                 {"attached": 9})
        for bad in cases:
            obj = {"audit": "attach"}
            obj.update(bad)
            with self.assertRaises(ValueError, msg=bad):
                m1validity.parse_attach_audit(write_tmp(self._line(obj)))


class CtxRuleTests(unittest.TestCase):
    def test_below_capacity_exact(self):
        ctx = {"rows": 192, "present_calls": 5000, "system_calls": 5000,
               "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 5000, "n_cgroup", 192,
                                     ctx_overflow=0), [])

    def test_below_capacity_violations(self):
        base = {"rows": 3, "present_calls": 100, "system_calls": 100,
                "unknown_calls": 0, "drops": 0}
        cases = [
            # A2: no present-vs-ops rule anymore — an inconsistent
            # triple fails the identity instead.
            ({"present_calls": 99}, "identity"),
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
                                              "single", 3, ctx_overflow=0)
            self.assertTrue(any(needle in reason for reason in reasons),
                            f"{delta} -> {reasons}")

    def test_contradiction_distinct_from_unreadable(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": None, "drops": 0}
        reasons = m1validity.check_ctx_leg(ctx, 100, "single", 3,
                                           ctx_overflow=0)
        self.assertTrue(any("contradiction" in reason for reason in reasons))

    def test_system_must_match_report_totals(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        reasons = m1validity.check_ctx_leg(ctx, 999, "single", 3,
                                           ctx_overflow=0)
        self.assertTrue(any("report totals" in reason for reason in reasons))

    def test_churn_full_rules(self):
        ctx = {"rows": 1024, "present_calls": 9000, "system_calls": 10000,
               "unknown_calls": 1000, "drops": 1000}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 10000, "churn_full", 1024,
                                     ctx_overflow=7),
            [])
        bad_rows = dict(ctx, rows=1023)
        self.assertTrue(m1validity.check_ctx_leg(
            bad_rows, 10000, "churn_full", 1024, ctx_overflow=7))
        bad_silent = dict(ctx, unknown_calls=0, drops=0,
                          present_calls=10000)
        self.assertTrue(m1validity.check_ctx_leg(
            bad_silent, 10000, "churn_full", 1024, ctx_overflow=7))

    def test_expected_rows_none_skips_pin(self):
        ctx = {"rows": 7, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 100, "single", None,
                                     ctx_overflow=0), [])

    def test_a2_no_driver_oracle_arithmetic(self):
        # A2 regression: kernel calls per roundtrip are kernel/shape
        # dependent (2 flat, 4 6.12-floor, plus allocs), so the
        # overlay pins no present-vs-ops relation — a 4x-shaped
        # consistent triple passes the exactness rules.
        ctx = {"rows": 3, "present_calls": 4008, "system_calls": 4008,
               "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 4008, "single", 3,
                                     ctx_overflow=0), [])

    def test_a2_sealed_612_diag_ctx_passes_exactness(self):
        # Replay of the sealed 6.12 diag ctx object
        # (cells/m1-diag-612-ctx, legs/leg00B-capture.stderr.log):
        # ops_total=1226880, KTOT=system=present=4907528. Row pin
        # skipped (diag kind): the floor splits kh across cryptd arms.
        # The overflow channel is asserted clean explicitly (F8): the
        # sealed file predates the counter, so full-cell replay of the
        # old cell documents the legacy-missing behavior instead.
        ctx = {"rows": 12, "present_calls": 4907528,
               "system_calls": 4907528, "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 4907528, "single", None,
                                     ctx_overflow=0), [])

    def test_churn_full_unreadable_present_or_drops(self):
        ctx = {"rows": 1024, "present_calls": None,
               "system_calls": 10000, "unknown_calls": 1000,
               "drops": 1000}
        reasons = m1validity.check_ctx_leg(ctx, 10000, "churn_full", 1024,
                                           ctx_overflow=7)
        self.assertTrue(any("unreadable" in reason for reason in reasons))

    def test_churn_full_unreadable_system_or_unknown(self):
        # F4 (codex review) regression: readable present/drops with
        # missing system+unknown (unreadable report TOTALS) must not
        # pass silently.
        ctx = {"rows": 1024, "present_calls": 9000,
               "system_calls": None, "unknown_calls": None,
               "drops": 1000}
        reasons = m1validity.check_ctx_leg(ctx, None, "churn_full", 1024,
                                           ctx_overflow=7)
        self.assertTrue(any("unreadable" in reason for reason in reasons))


class CtxOverflowTests(unittest.TestCase):
    # F8 (codex review): ctx_overflow_identities must be exported
    # (sealed coverage counter) and judged — 0 on below-cap shapes,
    # >= 1 on churn_full (first-per-kh lower bound, freeze §5).
    LOSS = ("ktot_gap", "ring_drops", "overflow_identities",
            "predrop_cfg_fail", "predrop_fret_fail", "predrop_arg_null",
            "predrop_chase_fail", "predrop_name_fail",
            "predrop_destroy_skip", "predrop_spare_6", "predrop_spare_7")

    def _report(self, overflow, totals_calls=100):
        counters = [{"name": name, "value": "0"} for name in self.LOSS]
        if overflow != "missing":
            counters.append({"name": "ctx_overflow_identities",
                             "value": overflow})
        return {"observations": [
            {"backend_payload": {"row": "totals",
                                "counts": {"calls": totals_calls}}}],
                "coverage": {
                    "aggregate_counts": {"counters": counters[:1]},
                    "detailed_events": {"counters": counters}},
                "verdict": {"status": "complete"}}

    def test_parse_overflow_counter(self):
        path = write_tmp(json.dumps(self._report("7")))
        self.assertEqual(m1validity.parse_ctx_overflow_counter(path), 7)
        path = write_tmp(json.dumps(self._report(0)))
        self.assertEqual(m1validity.parse_ctx_overflow_counter(path), 0)

    def test_parse_overflow_missing_or_mistyped(self):
        path = write_tmp(json.dumps(self._report("missing")))
        with self.assertRaises(ValueError):
            m1validity.parse_ctx_overflow_counter(path)
        path = write_tmp(json.dumps(self._report("seven")))
        with self.assertRaises(ValueError):
            m1validity.parse_ctx_overflow_counter(path)
        with self.assertRaises(ValueError):
            m1validity.parse_ctx_overflow_counter(
                Path("/nonexistent/report.json"))

    def test_parse_overflow_rejects_non_counter_values(self):
        # A3 review idea #7: the decoder must validate an unsigned
        # counter — permissive int() coerces False->0, 0.5->0,
        # True->1. Bools, floats, negatives, and non-digit strings
        # are all mistyped evidence, never zero.
        for bad in (False, True, 0.5, 2.7, -3, "-3", "3.0", "",
                    None, [3], {"v": 3}):
            path = write_tmp(json.dumps(self._report(bad)))
            with self.assertRaises(ValueError, msg=repr(bad)):
                m1validity.parse_ctx_overflow_counter(path)

    def test_parse_overflow_rejects_duplicates(self):
        # A3 review idea #7: two entries for the same counter are
        # contradictory evidence — first-match-wins would silently
        # ignore one of them.
        report = self._report("0")
        report["coverage"]["detailed_events"]["counters"].append(
            {"name": "ctx_overflow_identities", "value": "0"})
        path = write_tmp(json.dumps(report))
        with self.assertRaises(ValueError):
            m1validity.parse_ctx_overflow_counter(path)

    def test_parse_overflow_rejects_out_of_range(self):
        # A4 review M3: the serialized counter is a u64 — values
        # above 2**64-1 are mistyped evidence, never a count.
        for bad in (2 ** 64, 2 ** 100, str(2 ** 64)):
            path = write_tmp(json.dumps(self._report(bad)))
            with self.assertRaises(ValueError, msg=repr(bad)):
                m1validity.parse_ctx_overflow_counter(path)
        path = write_tmp(json.dumps(self._report(2 ** 64 - 1)))
        self.assertEqual(
            m1validity.parse_ctx_overflow_counter(path), 2 ** 64 - 1)

    def test_parse_overflow_rejects_null_counters(self):
        # A4 review M3: a null counters container must refuse as a
        # leg-invalid ValueError, never an uncaught TypeError.
        report = self._report("0")
        report["coverage"]["detailed_events"]["counters"] = None
        path = write_tmp(json.dumps(report))
        with self.assertRaises(ValueError):
            m1validity.parse_ctx_overflow_counter(path)

    def test_below_cap_overflow_rules(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 100, "single", 3,
                                     ctx_overflow=0), [])
        reasons = m1validity.check_ctx_leg(ctx, 100, "single", 3,
                                            ctx_overflow=2)
        self.assertTrue(any("ctx_overflow_identities=2" in reason
                            for reason in reasons))
        reasons = m1validity.check_ctx_leg(ctx, 100, "single", 3,
                                            ctx_overflow=None)
        self.assertTrue(any("unreadable" in reason for reason in reasons))

    def test_churn_full_overflow_rules(self):
        ctx = {"rows": 1024, "present_calls": 9000, "system_calls": 10000,
               "unknown_calls": 1000, "drops": 1000}
        self.assertEqual(
            m1validity.check_ctx_leg(ctx, 10000, "churn_full", 1024,
                                     ctx_overflow=1), [])
        reasons = m1validity.check_ctx_leg(ctx, 10000, "churn_full", 1024,
                                            ctx_overflow=0)
        self.assertTrue(any("want >= 1" in reason for reason in reasons))
        reasons = m1validity.check_ctx_leg(ctx, 10000, "churn_full", 1024,
                                            ctx_overflow=None)
        self.assertTrue(any("unreadable" in reason for reason in reasons))

    def _cell_dir(self, ctx, overflow, totals_calls):
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        line = ("kryprobe: telemetry "
                + json.dumps({"v": 1, "ctx": ctx}) + "\n")
        (legs / "leg00B-capture.stderr.log").write_text(line)
        (legs / "leg00B-report.json").write_text(
            json.dumps(self._report(overflow, totals_calls)))
        return tmp

    def test_pairs_overlay_extracts_counter(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        cell = self._cell_dir(ctx, "0", 100)
        judged = {"leg_id": "leg00B", "valid": True, "outcome": "valid",
                  "reasons": [], "driver": {"rc": 0}}
        leg = {"leg_id": "leg00B", "side": "B", "mode": "aggregation",
               "workload": "single"}
        entry = {"kind": "m1-pairs", "obs_a": "C", "obs_b": "C"}
        manifest = {"workloads": {"single": {"expected_rows": 3}}}
        out = CLI.apply_m1_ctx_overlay(cell, judged, leg, entry, manifest)
        self.assertTrue(out["valid"])
        self.assertEqual(out["ctx_overflow_identities"], 0)

    def test_pairs_overlay_missing_counter_invalid(self):
        ctx = {"rows": 3, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        cell = self._cell_dir(ctx, "missing", 100)
        judged = {"leg_id": "leg00B", "valid": True, "outcome": "valid",
                  "reasons": [], "driver": {"rc": 0}}
        leg = {"leg_id": "leg00B", "side": "B", "mode": "aggregation",
               "workload": "single"}
        entry = {"kind": "m1-pairs", "obs_a": "C", "obs_b": "C"}
        manifest = {"workloads": {"single": {"expected_rows": 3}}}
        out = CLI.apply_m1_ctx_overlay(cell, judged, leg, entry, manifest)
        self.assertFalse(out["valid"])
        self.assertTrue(any("ctx_overflow_identities" in reason
                            for reason in out["reasons"]))

    def test_diag_overlay_extracts_counter(self):
        ctx = {"rows": 12, "present_calls": 100, "system_calls": 100,
               "unknown_calls": 0, "drops": 0}
        cell = self._cell_dir(ctx, "0", 100)
        judged = {"leg_id": "leg00B", "valid": False, "outcome": "invalid",
                  "reasons": ["floor alloc calls=2"],
                  "driver": {"rc": 0}}
        leg = {"leg_id": "leg00B", "side": "B", "mode": "aggregation",
               "workload": "single"}
        out = CLI.apply_m1_diag_overlay(cell, judged, leg)
        self.assertEqual(out["diag"]["ctx_overflow_identities"], 0)
        self.assertEqual(out["diag"]["exactness"], [])


class SetVerdictTests(unittest.TestCase):
    def setUp(self):
        self.manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")

    def _pair(self, name, inside=True, seed=0, first=None):
        if inside:
            ratio_t, ratio_p = 0.99, 1.02
        else:
            idx = int(name[3:])
            ratio_t, ratio_p = (0.90, 1.20) if (idx + seed) % 2 == 0 \
                else (0.91, 1.21)
        if first is None:
            first = "A" if int(name[3:]) % 2 == 0 else "B"
        order = ("A", "B") if first == "A" else ("B", "A")
        return {"pair": name, "valid": True, "reasons": [],
                "order": order,
                "ratios": {"throughput": ratio_t, "p99": ratio_p}}

    def _pairs(self, n, inside=True, seed=0):
        return [self._pair(f"leg{i:02d}", inside, seed)
                for i in range(n)]

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
                [self._pair(f"leg{i:02d}", inside=False, seed=1)
                 for i in range(5, 10)]
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

    def test_eleven_valid_first_ten_decide(self):
        # F2 (codex review) regression: 11 valid pairs decide on the
        # first 10 in attempt order; the extra stays published but
        # non-deciding. The 11th pair is far outside budgets — the
        # verdict must still be PASS (it must not leak into B1/B2).
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        pairs = self._pairs(10, inside=True)
        outlier = self._pair("leg10", inside=True)
        outlier["ratios"] = {"throughput": 0.10, "p99": 9.99}
        pairs.append(outlier)
        real_form = CLI.form_pairs
        try:
            CLI.form_pairs = lambda cells: pairs
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "PASS")
            self.assertEqual(len(judged["deciding_pairs"]), 10)
            self.assertEqual(judged["non_deciding_pairs"], ["leg10"])
            self.assertEqual(judged["order_balance"],
                             {"first_a": 5, "first_b": 5})
        finally:
            CLI.form_pairs = real_form

    def test_unbalanced_deciding_is_invalid(self):
        # F2 (codex review) regression: a mid-run spare substitution
        # (leg03 lost, leg10 deciding) unbalances the aggregate order
        # to 6/4 even though every pair keeps its frozen parity — the
        # budgeted verdict must be INVALID, never a quiet PASS.
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        pairs = [self._pair(f"leg{i:02d}", inside=True)
                 for i in (0, 1, 2, 4, 5, 6, 7, 8, 9, 10)]
        self.assertEqual(len(pairs), 10)
        real_form = CLI.form_pairs
        try:
            CLI.form_pairs = lambda cells: pairs
            judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                      self._cells(None), self.manifest)
            self.assertEqual(judged["verdict"], "INVALID")
            self.assertTrue(any("balance" in reason
                                for reason in judged["reasons"]))
        finally:
            CLI.form_pairs = real_form

    def _m1_leg(self, pair, side, order):
        # Real-path legs (no form_pairs monkeypatch): in-budget
        # ratios (B/A throughput 0.99, p99 1.02).
        stats = {"throughput": 0.99 if side == "B" else 1.0,
                 "p50_ns": 100, "p99_ns": 102 if side == "B" else 100}
        return {"leg_id": f"leg{pair:02d}{side}", "side": side,
                "bulk": 0, "valid": True, "order": order,
                "stats": stats}

    def _m1_cell(self, name, pairs):
        legs = []
        for pair in pairs:
            first, second = ("A", "B") if pair % 2 == 0 else ("B", "A")
            legs.append(self._m1_leg(pair, first, 2 * pair))
            legs.append(self._m1_leg(pair, second, 2 * pair + 1))
        return {"cell": name, "errors": [], "legs": legs}

    def test_duplicate_attempt_ids_are_invalid(self):
        # N4 (A3 review): a spare staged with --start-pair 0
        # re-stages leg00/leg01 — form_pairs would silently
        # overwrite the main legs and undercount attempts. The M1
        # audit rejects before pairing (frozen pairing untouched).
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        main = self._m1_cell("m1-P-4K-single-cr", range(10))
        spare = self._m1_cell("m1-P-4K-single-cr-spare1", range(2))
        judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                  [main, spare], self.manifest)
        self.assertEqual(judged["verdict"], "INVALID")
        self.assertTrue(any("duplicate" in reason
                            for reason in judged["reasons"]))

    def test_gapped_attempt_indices_are_invalid(self):
        # N4: a spare staged with --start-pair 11 skips pair 10 —
        # silently short evidence. Contiguity from 0 is enforced.
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        main = self._m1_cell("m1-P-4K-single-cr", range(10))
        spare = self._m1_cell("m1-P-4K-single-cr-spare1", (11, 12))
        judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                  [main, spare], self.manifest)
        self.assertEqual(judged["verdict"], "INVALID")
        self.assertTrue(any("contiguous" in reason
                            for reason in judged["reasons"]))

    def test_malformed_leg_ids_are_invalid(self):
        # N4: legs.tsv carries no leg_id shape check — the audit is
        # the fail-closed backstop for corrupted attempt identity.
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        main = self._m1_cell("m1-P-4K-single-cr", range(10))
        main["legs"][0]["leg_id"] = "xx00A"
        judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                  [main], self.manifest)
        self.assertEqual(judged["verdict"], "INVALID")
        self.assertTrue(any("leg_id" in reason
                            for reason in judged["reasons"]))

    def test_contiguous_main_plus_spare_judges(self):
        # N4 control: main 00-09 + spare 10-11 (contiguous, no dups)
        # passes the audit and judges on the real path — 12 valid,
        # first 10 deciding, 5/5 balance, in-budget ratios → PASS.
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        main = self._m1_cell("m1-P-4K-single-cr", range(10))
        spare = self._m1_cell("m1-P-4K-single-cr-spare1", (10, 11))
        judged = CLI.judge_m1_set("m1-P-4K-single-cr", entry,
                                  [main, spare], self.manifest)
        self.assertEqual(judged["verdict"], "PASS")
        self.assertEqual(len(judged["deciding_pairs"]), 10)
        self.assertEqual(judged["non_deciding_pairs"],
                         ["leg10", "leg11"])


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
        # N6: the merge also reports the max shard meas start (min
        # 2000 / max 2500 here) so callers can publish actor skew.
        self.assertEqual(len(merged), 9)
        self.assertEqual(merged[8], 2500)
        rows = (tmp / "merged.csv").read_text().splitlines()[1:]
        seqs = sorted(int(line.split(",")[0]) for line in rows)
        # Globally unique seqs 0..4, each exactly twice (enc+dec).
        self.assertEqual(seqs, [0, 0, 1, 1, 2, 2, 3, 3, 4, 4])

    def _run_with_slow_merge(self, argv, delay_s=2.0):
        real_merge = M1DRIVER._merge_shards

        def slow_merge(shards, out):
            time.sleep(delay_s)
            return real_merge(shards, out)

        M1DRIVER._merge_shards = slow_merge
        try:
            return M1DRIVER.main(argv)
        finally:
            M1DRIVER._merge_shards = real_merge

    @unittest.skipUnless(_afalg_usable(), "AF_ALG cbc(aes) unavailable")
    def test_churn_tiny_run_merge_outside_window(self):
        # F6 (codex review) regression: the arrival merge must not
        # inflate meas_window_s; its cost rides merge_s. The 2s
        # injected merge would blow the 2s window under the old
        # (t_end-after-merge) order. First in-suite execution of the
        # churn path (previously never run anywhere).
        tmp = Path(tempfile.mkdtemp())
        ledger = str(tmp / "churn.csv")
        argv = [M1DRIVER.__file__, "skcipher", "4096", "2", "1",
               "--churn-every-ms", "500", "--churn-ops", "2", ledger]
        rc = self._run_with_slow_merge(argv)
        self.assertEqual(rc, 0)
        summary = json.loads(
            Path(ledger + ".summary.json").read_text())
        self.assertEqual(summary["arrivals"], 6)
        self.assertEqual(summary["fails"], 0)
        self.assertGreater(summary["ops_meas"], 0)
        self.assertGreaterEqual(summary["merge_s"], 2.0)
        # 2s window + reap skew, WITHOUT the injected 2s merge (the
        # old order would read ~4s+ here).
        self.assertLess(summary["meas_window_s"], 3.5)
        self.assertEqual(summary["rows_meas"], 2 * summary["ops_meas"])

    @unittest.skipUnless(os.geteuid() == 0,
                         "n_cgroup driver needs root (cgroup mkdir)")
    @unittest.skipUnless(_afalg_usable(), "AF_ALG cbc(aes) unavailable")
    def test_n_cgroup_tiny_run_merge_outside_window(self):
        # F6 (codex review) regression for the n_cgroup path (same
        # rule as churn): t_end stamps the reaped workload end, the
        # shard merge rides merge_s. First execution of this path
        # (previously never run anywhere).
        tmp = Path(tempfile.mkdtemp())
        ledger = str(tmp / "nc.csv")
        argv = [M1DRIVER.__file__, "skcipher", "4096", "2", "1",
               "--actors", "4", "--cgroups", "2", ledger]
        rc = self._run_with_slow_merge(argv)
        self.assertEqual(rc, 0)
        summary = json.loads(
            Path(ledger + ".summary.json").read_text())
        self.assertEqual(
            (summary["actors"], summary["cgroups"]), (4, 2))
        self.assertEqual(summary["fails"], 0)
        self.assertGreater(summary["ops_meas"], 0)
        self.assertGreaterEqual(summary["merge_s"], 2.0)
        self.assertLess(summary["meas_window_s"], 3.5)
        self.assertEqual(summary["rows_meas"], 2 * summary["ops_meas"])
        # N6: actor-start skew is published (informational, like
        # merge_s) and sane: within the measured window.
        self.assertIn("skew_s", summary)
        self.assertGreaterEqual(summary["skew_s"], 0.0)
        self.assertLessEqual(summary["skew_s"],
                             summary["meas_window_s"])
        tag = f"{M1DRIVER.M1_CGROUP_TAG}-{os.getpid()}"
        leftovers = sorted(Path(M1DRIVER.M1_CGROUP_BASE).glob(f"{tag}-*"))
        self.assertEqual(leftovers, [])

    @unittest.skipUnless(os.geteuid() == 0,
                         "n_cgroup driver needs root (cgroup mkdir)")
    @unittest.skipUnless(_afalg_usable(), "AF_ALG cbc(aes) unavailable")
    def test_n_cgroup_cleanup_after_t_end(self):
        # N6 (A3 review) structural: cgroup teardown is parent-side
        # overhead — every rmdir must land AFTER the stamped t_end,
        # never inside the measure window. Timestamped via a
        # recording os.rmdir wrapper (no timing flakes: ordering,
        # not duration, is asserted).
        tmp = Path(tempfile.mkdtemp())
        ledger = str(tmp / "nc-clean.csv")
        argv = [M1DRIVER.__file__, "skcipher", "4096", "1", "0",
               "--actors", "2", "--cgroups", "1", ledger]
        rmdir_at = []
        real_rmdir = os.rmdir

        def recording_rmdir(path, *args, **kwargs):
            rmdir_at.append(time.monotonic_ns())
            return real_rmdir(path, *args, **kwargs)

        os.rmdir = recording_rmdir
        try:
            rc = M1DRIVER.main(argv)
        finally:
            os.rmdir = real_rmdir
        self.assertEqual(rc, 0)
        summary = json.loads(
            Path(ledger + ".summary.json").read_text())
        self.assertEqual(summary["fails"], 0)
        self.assertTrue(rmdir_at, "expected cgroup teardown calls")
        for stamp in rmdir_at:
            self.assertGreaterEqual(stamp, summary["t_end_ns"])


class DiagVerdictTests(unittest.TestCase):
    # F3 (codex review): the m1-612-ctx diag's C leg is frozen-invalid
    # BY DESIGN (aggregation + 6.12-floor subject shape), so the frozen
    # legs-valid gate cannot adjudicate it. The diag verdict rests on
    # structure + quiet + driver + capture + attach 9/9 + A2 exactness.
    def setUp(self):
        self.manifest = m1manifest.load_manifest(
            ROOT / "tests" / "kcrypto_perf" / "cells-m1.json")
        self.entry = CLI.find_diag(self.manifest, "m1-diag-612-ctx")

    def _leg(self, **over):
        leg = {"leg_id": "leg00B", "side": "B", "mode": "aggregation",
               "cls": "P-4K", "workload": "single",
               "valid": False, "outcome": "invalid",
               "reasons": ["floor alloc calls=2"],
               "driver": {"rc": 0, "ops_total": 1226880},
               "driver_rc": 0, "driver_timeout": 0, "capture_rc": 3,
               "stats": {"throughput": 1.0}, "observer": {},
               "diag": {
                   "attach": {"attached": 9, "expected": 9},
                   "ctx": {"rows": 12, "present_calls": 4907528,
                           "system_calls": 4907528, "unknown_calls": 0,
                           "drops": 0},
                   "totals_calls": 4907528, "exactness": []}}
        leg.update(over)
        return leg

    def _cell(self, legs):
        return {"cell": "fake-diag", "errors": [],
                "spec_boot_invalid": False,
                "quiet": {"totals": {"calls": 0}, "valid": True,
                          "reasons": []},
                "legs": legs}

    def test_frozen_invalid_leg_passes_diag(self):
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([self._leg()]))
        self.assertEqual(judged["verdict"], "PASS")
        self.assertEqual(judged["attach"], {"attached": 9, "expected": 9})
        # The frozen shape verdict stays visible for transparency.
        self.assertFalse(judged["leg"]["frozen_shape"]["valid"])

    def test_judge_diag_dispatches_m1_branch(self):
        judged = CLI.judge_diag("m1-diag-612-ctx",
                                self._cell([self._leg()]), self.manifest)
        self.assertEqual(judged["verdict"], "PASS")

    def test_diag_requires_single_b_leg(self):
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([]))
        self.assertEqual(judged["verdict"], "INVALID")
        judged = CLI.judge_m1_diag(
            "m1-diag-612-ctx", self.entry,
            self._cell([self._leg(side="A")]))
        self.assertEqual(judged["verdict"], "INVALID")

    def test_diag_requires_quiet(self):
        cell = self._cell([self._leg()])
        cell["spec_boot_invalid"] = True
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry, cell)
        self.assertEqual(judged["verdict"], "INVALID")
        self.assertTrue(any("quiet" in reason
                            for reason in judged["reasons"]))

    def test_diag_requires_clean_driver_and_capture(self):
        for bad in ({"driver_rc": 1}, {"driver_timeout": 1},
                    {"capture_rc": 1}, {"capture_rc": None}):
            judged = CLI.judge_m1_diag(
                "m1-diag-612-ctx", self.entry,
                self._cell([self._leg(**bad)]))
            self.assertEqual(judged["verdict"], "INVALID", bad)
        leg = self._leg()
        leg["driver"] = {"rc": 2}
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")

    def test_diag_requires_attach_9_9(self):
        leg = self._leg()
        leg["diag"] = {"attach": {"attached": 8, "expected": 9},
                       "ctx": leg["diag"]["ctx"],
                       "totals_calls": 4907528, "exactness": []}
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")
        leg = self._leg()
        leg["diag"] = {"attach_error": "no attach audit object"}
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")

    def test_diag_requires_exactness(self):
        leg = self._leg()
        leg["diag"] = dict(leg["diag"],
                           exactness=["single unknown=5, want 0"])
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")
        leg = self._leg()
        del leg["diag"]
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")

    def test_diag_rejects_vacuous_observation(self):
        # N2 (A3 review): driver ran positive traffic and attach is
        # 9/9, but BOTH sensor ledgers read zero — agreeing zeros
        # must not PASS (the frozen driver<->sensor reconciliation
        # the overlay docstring cites does not run on the diag path).
        leg = self._leg()
        leg["diag"] = {
            "attach": {"attached": 9, "expected": 9},
            "ctx": {"rows": 0, "present_calls": 0, "system_calls": 0,
                    "unknown_calls": 0, "drops": 0},
            "totals_calls": 0, "exactness": []}
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")
        self.assertTrue(any("observation" in reason
                            for reason in judged["reasons"]))

    def test_diag_rejects_partial_observation(self):
        # N2 variant: sensors agree exactly but saw ~half the
        # workload (ratio 0.98x vs flat 2x / floor 4x) — gross
        # partial misses must not PASS either.
        leg = self._leg()
        leg["diag"] = {
            "attach": {"attached": 9, "expected": 9},
            "ctx": {"rows": 6, "present_calls": 1200000,
                    "system_calls": 1200000, "unknown_calls": 0,
                    "drops": 0},
            "totals_calls": 1200000, "exactness": []}
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "INVALID")
        self.assertTrue(any("ratio" in reason
                            for reason in judged["reasons"]))

    def test_diag_accepts_flat_ratio(self):
        # N2 control (anti-A1): the band must contain the FLAT shape
        # too (7.x canary leg00B: 1595873/797936 = 2.00000125) —
        # the diag must not overfit the 4x floor equation.
        leg = self._leg()
        leg["driver"] = {"rc": 0, "ops_total": 797936}
        leg["diag"] = {
            "attach": {"attached": 9, "expected": 9},
            "ctx": {"rows": 3, "present_calls": 1595873,
                    "system_calls": 1595873, "unknown_calls": 0,
                    "drops": 0},
            "totals_calls": 1595873, "exactness": []}
        judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                   self._cell([leg]))
        self.assertEqual(judged["verdict"], "PASS")

    def test_diag_rejects_missing_driver_ops(self):
        # N2: a missing/non-positive driver denominator is INVALID
        # (fail-closed — never a vacuous ratio).
        for bad_ops in (None, 0, -5, True, "1226880"):
            leg = self._leg()
            leg["driver"] = {"rc": 0, "ops_total": bad_ops}
            judged = CLI.judge_m1_diag("m1-diag-612-ctx", self.entry,
                                       self._cell([leg]))
            self.assertEqual(judged["verdict"], "INVALID", bad_ops)


class SuccessorShardDirTests(unittest.TestCase):
    """Guest-local shard transport (A12 item 4, H-C): the driver
    accepts ``--shard-dir`` so shards + per-shard summaries live
    on guest-local storage; only the merged ledger + summary
    land on the shared ledger path. Default (flag absent) keeps
    the frozen ledger-sibling layout byte for byte."""

    def _argv(self, *flags):
        return ["drv", "skcipher", "4096", "30", "10", "--actors",
                "2", "--cgroups", "1", *flags, "/run/led/ledger.csv"]

    def test_parse_shard_dir_flag(self):
        opts = M1DRIVER.parse_args(self._argv("--shard-dir", "/tmp/g"))
        self.assertEqual(opts["shard_dir"], "/tmp/g")

    def test_parse_shard_dir_defaults_none(self):
        opts = M1DRIVER.parse_args(self._argv())
        self.assertIsNone(opts["shard_dir"])

    def test_parse_shard_dir_rejects_empty(self):
        self.assertIsNone(self._argv_ok("--shard-dir", ""))

    def _argv_ok(self, *flags):
        return M1DRIVER.parse_args(self._argv(*flags))

    def test_shard_paths_default_are_ledger_siblings(self):
        opts = M1DRIVER.parse_args(self._argv())
        self.assertEqual(
            M1DRIVER._shard_paths(opts, 2, "shard"),
            ["/run/led/ledger.csv.shard-0",
             "/run/led/ledger.csv.shard-1"])

    def test_shard_paths_guest_local_dir(self):
        opts = M1DRIVER.parse_args(self._argv("--shard-dir", "/tmp/g"))
        self.assertEqual(
            M1DRIVER._shard_paths(opts, 2, "shard"),
            ["/tmp/g/ledger.csv.shard-0",
             "/tmp/g/ledger.csv.shard-1"])

    def test_shard_paths_arrival_tag(self):
        opts = M1DRIVER.parse_args(self._argv("--shard-dir", "/tmp/g"))
        self.assertEqual(
            M1DRIVER._shard_paths(opts, 1, "arrival"),
            ["/tmp/g/ledger.csv.arrival-0"])

    def _timeout_legs(self, shards=True, merged=True):
        legs = Path(tempfile.mkdtemp())
        if shards:
            (legs / "leg00B-driver.csv.shard-0").write_text(
                "seq,phase,op,dt_ns\n")
        if merged:
            (legs / "leg00B-driver.csv").write_text(
                "seq,phase,op,dt_ns\n")
            (legs / "leg00B-driver.csv.summary.json").write_text(
                "{}")
        return legs

    def test_timeout_child_hang_signature(self):
        # H-C in-matrix signature (FORENSICS-2): shard files
        # exist but the merge never landed — the runner owes
        # this leg a fresh attempt id, not a verdict.
        legs = self._timeout_legs(shards=True, merged=False)
        self.assertTrue(
            M1DRIVER.timeout_is_child_hang(str(legs), "leg00B"))

    def test_timeout_merged_is_not_child_hang(self):
        legs = self._timeout_legs(shards=True, merged=True)
        self.assertFalse(
            M1DRIVER.timeout_is_child_hang(str(legs), "leg00B"))

    def test_timeout_no_shards_is_not_child_hang(self):
        legs = self._timeout_legs(shards=False, merged=False)
        self.assertFalse(
            M1DRIVER.timeout_is_child_hang(str(legs), "leg00B"))


class SuccessorManifestTests(unittest.TestCase):
    """Manifest v3 is the successor epoch switch (A12): same v2
    40-set shape plus the required per-program lane-surface pin
    the successor judge gates on."""

    def _v3_doc(self):
        doc = json.loads((ROOT / "tests" / "kcrypto_perf"
                          / "cells-m1.json").read_text())
        doc["manifest_version"] = 3
        doc["global"]["expected_programs"] = 9
        return doc

    def _write(self, doc):
        return write_tmp(json.dumps(doc), suffix=".json")

    def test_version_three_loads(self):
        manifest = m1manifest.load_manifest(self._write(self._v3_doc()))
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertIn("_manifest_sha256", manifest)

    def test_version_three_requires_lane_pin(self):
        doc = self._v3_doc()
        del doc["global"]["expected_programs"]
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(self._write(doc))

    def test_version_three_rejects_zero_lane_pin(self):
        doc = self._v3_doc()
        doc["global"]["expected_programs"] = 0
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(self._write(doc))

    def test_version_four_rejects(self):
        doc = self._v3_doc()
        doc["manifest_version"] = 4
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(self._write(doc))

    def test_shard_dir_loads(self):
        doc = self._v3_doc()
        doc["global"]["shard_dir"] = "/tmp/kryprobe-shards"
        manifest = m1manifest.load_manifest(self._write(doc))
        self.assertEqual(manifest["global"]["shard_dir"],
                         "/tmp/kryprobe-shards")

    def test_shard_dir_rejects_relative(self):
        doc = self._v3_doc()
        doc["global"]["shard_dir"] = "tmp/relative"
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(self._write(doc))

    def test_shard_dir_rejects_empty(self):
        doc = self._v3_doc()
        doc["global"]["shard_dir"] = ""
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(self._write(doc))

    def test_shard_dir_rejects_shell_metacharacters(self):
        # The staged path is sourced inside double quotes and
        # word-split at use — only a safe charset is honest.
        for bad in ("/tmp/$(printf x)", "/tmp/`id`",
                    "/tmp/a b", "/tmp/a;b", '/tmp/a"b',
                    "/tmp/a'b", "/tmp/a&b", "/tmp/a|b"):
            doc = self._v3_doc()
            doc["global"]["shard_dir"] = bad
            with self.assertRaises(m1manifest.InputError,
                                   msg=f"path {bad!r}"):
                m1manifest.load_manifest(self._write(doc))

    def test_shard_dir_accepts_safe_charset(self):
        doc = self._v3_doc()
        doc["global"]["shard_dir"] = "/tmp/kryprobe-shards_v2/x-y"
        manifest = m1manifest.load_manifest(self._write(doc))
        self.assertEqual(manifest["global"]["shard_dir"],
                         "/tmp/kryprobe-shards_v2/x-y")


class SuccessorTruthTests(unittest.TestCase):
    """Per-leg driver-truth oracle: n_cgroup K6-1 sealed numbers,
    small flat synthetic, 6.12 floor form (frozen floor rows:
    2 ops x 2 arms x ops + 2 pinned allocs)."""

    def test_k6_1_flat_truth(self):
        self.assertEqual(
            successorvalidity.successor_truth(
                ops=4506576, alloc=64, kernel="7.0.14"),
            9013216)

    def test_small_flat_truth(self):
        self.assertEqual(
            successorvalidity.successor_truth(
                ops=100, alloc=2, kernel="7.0.14"),
            202)

    def test_floor_truth(self):
        self.assertEqual(
            successorvalidity.successor_truth(
                ops=100, alloc=1, kernel="6.12.111"),
            402)

    def test_unknown_kernel_refuses(self):
        with self.assertRaises(ValueError):
            successorvalidity.successor_truth(
                ops=100, alloc=1, kernel="9.9.9")


LOSS_ZERO = [("ktot_gap", 0), ("ring_drops", 0),
             ("overflow_identities", 0), ("predrop_cfg_fail", 0),
             ("predrop_fret_fail", 0), ("predrop_arg_null", 0),
             ("predrop_chase_fail", 0), ("predrop_name_fail", 0),
             ("predrop_destroy_skip", 0), ("predrop_spare_6", 0),
             ("predrop_spare_7", 0)]


def _api_report(observed, misses, gap=0):
    counters = [{"name": n, "value": v} for n, v in LOSS_ZERO]
    counters[0] = {"name": "ktot_gap", "value": gap}
    agg = [{"name": "kernel_misses", "value": misses},
           {"name": "snapshot_agg_calls", "value": observed},
           {"name": "snapshot_totals_calls", "value": observed}]
    alloc = 2
    half = (observed - alloc) // 2
    rows = [
        {"backend_payload": {
            "row": "agg", "family": "skcipher", "op": "encrypt",
            "driver": "flat",
            "counts": {"calls": half, "ok": half, "errors": 0,
                       "queued": 0}}},
        {"backend_payload": {
            "row": "agg", "family": "skcipher", "op": "decrypt",
            "driver": "flat",
            "counts": {"calls": observed - alloc - half,
                       "ok": observed - alloc - half, "errors": 0,
                       "queued": 0}}},
        {"backend_payload": {
            "row": "agg", "family": "any", "op": "alloc",
            "algorithm": "cbc(aes)",
            "counts": {"calls": alloc, "ok": alloc, "errors": 0,
                       "queued": 0}}},
        {"backend_payload": {
            "row": "totals",
            "counts": {"calls": observed, "errors": 0, "ok": observed,
                       "queued": 0}}}]
    return {
        "observations": rows,
        "coverage": {
            "aggregate_counts": {"counters": agg + counters},
            "detailed_events": {"counters": [
                {"name": "ctx_overflow_identities", "value": 0}]}},
        "verdict": {"status": "partial"}}


def _ctx_line(rows, present, system):
    return ('kryprobe: telemetry {"v":1,"ctx":{"rows":%d,'
            '"present_calls":%d,"system_calls":%d,'
            '"unknown_calls":0,"drops":0}}\n') % (rows, present, system)


def _miss_line(programs, delta):
    return ('kryprobe: telemetry {"v":1,"misses":{"programs":%d,'
            '"miss_delta":%d,"run_delta":null}}\n') % (programs, delta)


def _workload_doc(system_total):
    calls = str(system_total)
    return {
        "schema": "kryprobe.workload-report.v2", "session": {},
        "interval": {"consistency": "unproven"},
        "profile": "api-returns", "boundary": "api_return",
        "dictionary": {}, "contexts": [{"calls": calls}],
        "ledger": {"system_total": calls, "per_context_sum": calls,
                   "unknown": "0", "consistency": "unproven",
                   "gap_unreconciled": True, "system_saturated": False,
                   "per_context_saturated": False,
                   "refused_inserts": "0"},
        "partition": {"matched": calls, "nonmatched": "0",
                      "unknown_match": "0"},
        "selectors": {"kind": "none"},
        "scope": {"capture_scope": "system",
                  "report_scope": "unscoped", "group_by": "none"},
        "metadata": {"status": "available", "reason": None},
        "coverage": {"capture": "partial", "attribution": "partial",
                     "metadata": "available",
                     "correlation": "complete"}}


class SuccessorOverlayTests(unittest.TestCase):
    """Successor epoch wiring (A12): manifest v3 legs run the
    truth-equation gate after the M1 overlay; v2 cells never
    see it. Synthetic small numbers (ops=100, alloc=2,
    truth=202); K6-scale oracles live in test_successor.py."""

    OPS, ALLOC, MISS, OBSERVED = 100, 2, 2, 200

    def _cell(self, files):
        root = Path(tempfile.mkdtemp())
        legs = root / "legs"
        legs.mkdir()
        for name, content in files.items():
            (legs / name).write_text(content)
        return root

    def _manifest(self, version, rows=192):
        doc = {"manifest_version": version,
               "workloads": {"n_cgroup": {"expected_rows": rows}}}
        if version == 3:
            doc["global"] = {"expected_programs": 9}
        return doc

    def _c_leg(self):
        return {"leg_id": "leg00B", "side": "B", "mode": "aggregation",
                "cls": "P-4K", "driver": "skcipher",
                "workload": "n_cgroup", "bulk": False, "threads": 2}

    def _c_files(self, misses=2, gap=0, observed=200, rows=192):
        report = _api_report(observed, misses, gap)
        if misses is None:
            report["coverage"]["aggregate_counts"]["counters"] = [
                c for c in report["coverage"]["aggregate_counts"]
                ["counters"] if c["name"] != "kernel_misses"]
        stderr = _ctx_line(rows, observed, observed)
        if misses is not None:
            stderr += _miss_line(9, misses)
        return {"leg00B-report.json": json.dumps(report),
                "leg00B-capture.stderr.log": stderr,
                "leg00B-driver.csv.summary.json": json.dumps(
                    {"ops_total": 100})}

    def _c_entry(self):
        return {"kind": "m1-pairs", "obs_a": "R", "obs_b": "C"}

    def _judged(self):
        return {"valid": True, "outcome": "valid", "reasons": [],
                "driver": {"ops_total": self.OPS}}

    def _overlay(self, cell, judged, leg, entry, manifest):
        return CLI.apply_m1_ctx_overlay(cell, judged, leg, entry,
                                        manifest, kernel="7.0.14")

    def test_v3_c_leg_consistent_valid(self):
        cell = self._cell(self._c_files())
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertTrue(out["valid"], out.get("reasons"))
        self.assertEqual(out.get("reasons"), [])

    def test_v3_c_leg_missing_misses_invalid(self):
        cell = self._cell(self._c_files(misses=None))
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("successor" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v3_c_leg_equation_off_invalid(self):
        cell = self._cell(self._c_files(misses=5))
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("successor" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v2_c_leg_ignores_successor_equation(self):
        cell = self._cell(self._c_files(misses=5))
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(2))
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_v3_c_leg_lane_gap_invalid(self):
        cell = self._cell(self._c_files(gap=1))
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("ktot_gap" in r for r in out["reasons"]),
                        out["reasons"])

    def _r_leg(self):
        return {"leg_id": "leg00A", "side": "A", "mode": "aggregation",
                "cls": "P-4K", "driver": "skcipher",
                "workload": "n_cgroup", "bulk": False, "threads": 2}

    def _r_files(self, misses=2):
        files = self._c_files(misses=misses)
        files["leg00A-report.json"] = files.pop("leg00B-report.json")
        if misses is None:
            files["leg00A-capture.stderr.log"] = ""
        else:
            files["leg00A-capture.stderr.log"] = _miss_line(9, misses)
        return files

    def test_v3_r_leg_ignores_equation_without_surfaces(self):
        # R disposition (A12 D2): v3 R legs keep frozen per-op
        # exactness and never run the truth equation — but any
        # present miss surface invalidates (R1 bytes cannot
        # emit one, so presence is an anomaly).
        cell = self._cell(self._r_files(misses=None))
        out = self._overlay(cell, self._judged(), self._r_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_v3_r_leg_miss_evidence_invalid(self):
        cell = self._cell(self._r_files(misses=5))
        out = self._overlay(cell, self._judged(), self._r_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("miss" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v3_r_leg_detailed_miss_counter_invalid(self):
        # The R probe scans both coverage dims: a miss
        # counter smuggled into detailed_events is the same
        # anomaly as one in aggregate_counts.
        files = self._r_files(misses=None)
        report = json.loads(files["leg00A-report.json"])
        report["coverage"]["detailed_events"]["counters"].append(
            {"name": "kernel_misses", "value": 5})
        files["leg00A-report.json"] = json.dumps(report)
        cell = self._cell(files)
        out = self._overlay(cell, self._judged(), self._r_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])

    def test_v3_c_leg_detailed_miss_counter_invalid(self):
        # Same anomaly on C: kernel_misses belongs to
        # aggregate_counts only; a detailed_events twin is a
        # contradictory receipt.
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        report["coverage"]["detailed_events"]["counters"].append(
            {"name": "kernel_misses", "value": 5})
        files["leg00B-report.json"] = json.dumps(report)
        cell = self._cell(files)
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])

    def test_v3_r_leg_duplicate_member_report_invalid(self):
        # Regression: a decode failure in the presence probe
        # must invalidate, never read as "absent".
        files = self._r_files(misses=None)
        files["leg00A-report.json"] = (
            '{"observations": [], "coverage": {"aggregate_counts": '
            '{"counters": [{"name": "kernel_misses", "value": 1, '
            '"value": 0}]}, "detailed_events": {"counters": []}}}')
        cell = self._cell(files)
        out = self._overlay(cell, self._judged(), self._r_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])

    def test_v3_driver_summary_duplicates_invalid(self):
        # Frozen truth decoding last-wins; the v3 overlay
        # re-validates the summary bytes strictly (C and M).
        for files, leg, entry, manifest in (
                (self._c_files(), self._c_leg(), self._c_entry(),
                 self._manifest(3)),
                (self._m_files(), self._m_leg(), self._m_entry(),
                 self._m_manifest(3))):
            files["leg00B-driver.csv.summary.json"] = (
                '{"ops_total": 999, "ops_total": 100}')
            cell = self._cell(files)
            out = self._overlay(cell, self._judged(), leg, entry,
                                manifest)
            self.assertFalse(out["valid"], (leg, entry))
            self.assertTrue(any("summary" in r
                                for r in out["reasons"]),
                            out["reasons"])

    def test_v3_m_workload_duplicates_invalid(self):
        # The frozen workload decoder last-wins; v3
        # re-validates the raw bytes (system_total and
        # metadata status twins both refuse).
        for dup in ('"system_total": "201", "system_total": "200"',
                    '"status": "unavailable", "status": "available"'):
            files = self._m_files()
            text = files["leg00B-report.workload-json"]
            if "system_total" in dup:
                text = text.replace('"system_total": "200"', dup, 1)
            else:
                text = text.replace('"status": "available"', dup, 1)
            files["leg00B-report.workload-json"] = text
            cell = self._cell(files)
            out = self._overlay(cell, self._judged(), self._m_leg(),
                                self._m_entry(), self._m_manifest(3))
            self.assertFalse(out["valid"], dup)

    def test_v2_m_workload_duplicates_keep_frozen(self):
        # Frozen preservation: v2 judges duplicate members
        # by last-wins (the freeze pins decoder behavior) —
        # strict JSON is a v3 successor rule only.
        files = self._m_files()
        text = files["leg00B-report.workload-json"]
        text = text.replace('"system_total": "200"',
                            '"system_total": "201", '
                            '"system_total": "200"', 1)
        files["leg00B-report.workload-json"] = text
        cell = self._cell(files)
        out = self._overlay(cell, self._judged(), self._m_leg(),
                            self._m_entry(), self._m_manifest(2))
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_v3_r_leg_frozen_exactness_enforced(self):
        # Full chain: a missy v3 R leg (equation-consistent)
        # still fails frozen per-op exactness — the stricter
        # gate R keeps.
        files = self._r_files(misses=2)
        # _r_files already builds missy per-op rows (99/99 vs
        # ops 100) with a reconciled aggregate sum.
        files["leg00A-driver.csv.summary.json"] = json.dumps({
            "ops_total": 100, "ops_meas": 100, "rows_meas": 4,
            "rc": 0, "fails": 0, "late": 0, "paced": 0, "threads": 2,
            "meas_window_s": 30.0, "t_warm_start_ns": 0,
            "t_meas_start_ns": 10_000_000_000,
            "t_end_ns": 40_000_000_000})
        files["leg00A-driver-rc.txt"] = \
            "driver_rc=0\ndriver_timeout=0\n"
        files["leg00A-driver.csv"] = (
            "seq,phase,op,dt_ns\n0,meas,encrypt,5\n0,meas,decrypt,7\n"
            "1,meas,encrypt,5\n1,meas,decrypt,7\n")
        files["leg00A-capture-rc.txt"] = "capture_rc=0\n"
        cell = self._cell(files)
        judged = CLI.judge_leg(cell, self._r_leg(), "7.0.14",
                               (10.0, 30.0), successor=False)
        self.assertFalse(judged["valid"])
        self.assertTrue(any("want 100" in r for r in judged["reasons"]),
                        judged["reasons"])

    def test_m1_leg_obs_derivation(self):
        entry = {"kind": "m1-pairs", "obs_a": "R", "obs_b": "C"}
        self.assertEqual(
            CLI._m1_leg_obs({"side": "A"}, entry), "R")
        self.assertEqual(
            CLI._m1_leg_obs({"side": "B"}, entry), "C")
        self.assertIsNone(
            CLI._m1_leg_obs({"side": "B"}, {"kind": "m1-612-ctx"}))

    def _driver_files(self, leg_id="leg00B"):
        return {
            f"{leg_id}-driver.csv.summary.json": json.dumps({
                "ops_total": 100, "ops_meas": 100, "rows_meas": 4,
                "rc": 0, "fails": 0, "late": 0, "paced": 0,
                "threads": 2, "meas_window_s": 30.0,
                "t_warm_start_ns": 0,
                "t_meas_start_ns": 10_000_000_000,
                "t_end_ns": 40_000_000_000}),
            f"{leg_id}-driver-rc.txt":
                "driver_rc=0\ndriver_timeout=0\n",
            f"{leg_id}-driver.csv": (
                "seq,phase,op,dt_ns\n0,meas,encrypt,5\n"
                "0,meas,decrypt,7\n1,meas,encrypt,5\n"
                "1,meas,decrypt,7\n"),
            f"{leg_id}-capture-rc.txt": "capture_rc=0\n"}

    def test_v3_result_errors_invalid(self):
        # The v3 provisional gate keeps the frozen
        # zero-error/zero-queued result checks the count
        # supersession must not drop.
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        for obs in report["observations"]:
            payload = obs["backend_payload"]
            if payload.get("row") == "agg" and \
                    payload.get("op") == "encrypt":
                payload["counts"]["errors"] = 1
        files["leg00B-report.json"] = json.dumps(report)
        files.update(self._driver_files())
        cell = self._cell(files)
        judged = CLI.judge_leg(cell, self._c_leg(), "7.0.14",
                               (10.0, 30.0), successor=True)
        self.assertFalse(judged["valid"])
        self.assertTrue(any("errors" in r for r in judged["reasons"]),
                        judged["reasons"])

    def test_v3_result_queued_invalid(self):
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        for obs in report["observations"]:
            payload = obs["backend_payload"]
            if payload.get("row") == "agg" and \
                    payload.get("op") == "decrypt":
                payload["counts"]["queued"] = 1
        files["leg00B-report.json"] = json.dumps(report)
        files.update(self._driver_files())
        cell = self._cell(files)
        judged = CLI.judge_leg(cell, self._c_leg(), "7.0.14",
                               (10.0, 30.0), successor=True)
        self.assertFalse(judged["valid"])
        self.assertTrue(any("queued" in r for r in judged["reasons"]),
                        judged["reasons"])

    def test_v3_coerced_loss_counter_invalid(self):
        # Frozen int(False) == 0: the v3 loss gate must
        # strict-parse, never inherit the coercion.
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        for counter in report["coverage"]["aggregate_counts"][
                "counters"]:
            if counter["name"] == "predrop_chase_fail":
                counter["value"] = False
        files["leg00B-report.json"] = json.dumps(report)
        files.update(self._driver_files())
        cell = self._cell(files)
        judged = CLI.judge_leg(cell, self._c_leg(), "7.0.14",
                               (10.0, 30.0), successor=True)
        self.assertFalse(judged["valid"])

    def test_v3_snapshot_contradiction_invalid(self):
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        for counter in report["coverage"]["aggregate_counts"][
                "counters"]:
            if counter["name"] == "snapshot_agg_calls":
                counter["value"] = 1
        files["leg00B-report.json"] = json.dumps(report)
        cell = self._cell(files)
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("snapshot" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v3_m_leg_churn_full_saturated_valid(self):
        # Sealed shape (4K-churn_full-mr): 1024 rows, unknown
        # == drops > 0, refused > 0 — saturation must pass
        # the M truth gate, never trip a phantom lane gap.
        rows = [{"calls": "5798"}] + [{"calls": "0"}] * 1023
        doc = _workload_doc(13600)
        doc["contexts"] = rows
        doc["ledger"]["per_context_sum"] = "5798"
        doc["ledger"]["unknown"] = "0"
        doc["ledger"]["refused_inserts"] = "7802"
        doc["partition"]["matched"] = "5798"
        files = {"leg00B-report.workload-json": json.dumps(doc),
                 "leg00B-capture.stderr.log": (
                     'kryprobe: telemetry {"v":1,"ctx":{"rows":1024,'
                     '"present_calls":5798,"system_calls":13600,'
                     '"unknown_calls":7802,"drops":7802}}\n'
                     + _miss_line(9, 0)),
                 "leg00B-driver.csv.summary.json": json.dumps(
                     {"ops_total": 6799})}
        cell = self._cell(files)
        judged = {"valid": True, "outcome": "valid", "reasons": [],
                  "driver": {"ops_total": 6799}}
        leg = dict(self._m_leg(), workload="churn_full", threads=2)
        manifest = {"manifest_version": 3,
                    "global": {"expected_programs": 9},
                    "workloads": {"churn_full": {"expected_rows": 1024}}}
        out = CLI.apply_m1_ctx_overlay(cell, judged, leg,
                                       self._m_entry(), manifest,
                                       kernel="7.0.14")
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_v3_provisional_loss_gate_pins_kdrops(self):
        # A12 item 2 (folded form): a nonzero drop-site
        # counter fails the v3 pre-gate even when the truth
        # equation would hold — KDROPS sites stay pinned.
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        for counter in report["coverage"]["aggregate_counts"][
                "counters"]:
            if counter["name"] == "predrop_chase_fail":
                counter["value"] = 1
        files["leg00B-report.json"] = json.dumps(report)
        files["leg00B-driver.csv.summary.json"] = json.dumps({
            "ops_total": 100, "ops_meas": 100, "rows_meas": 4,
            "rc": 0, "fails": 0, "late": 0, "paced": 0, "threads": 2,
            "meas_window_s": 30.0, "t_warm_start_ns": 0,
            "t_meas_start_ns": 10_000_000_000,
            "t_end_ns": 40_000_000_000})
        files["leg00B-driver-rc.txt"] = \
            "driver_rc=0\ndriver_timeout=0\n"
        files["leg00B-driver.csv"] = (
            "seq,phase,op,dt_ns\n0,meas,encrypt,5\n0,meas,decrypt,7\n"
            "1,meas,encrypt,5\n1,meas,decrypt,7\n")
        files["leg00B-capture-rc.txt"] = "capture_rc=0\n"
        cell = self._cell(files)
        judged = CLI.judge_leg(cell, self._c_leg(), "7.0.14",
                               (10.0, 30.0), successor=True)
        self.assertFalse(judged["valid"])
        self.assertTrue(any("predrop_chase_fail" in r
                            for r in judged["reasons"]),
                        judged["reasons"])

    def test_v3_unavailable_miss_terminal_invalid(self):
        # A12 item 2 (fence mechanism): a fence-unproven miss
        # terminal prints unavailable — the successor leg
        # refuses it, never zero-fills.
        files = self._c_files()
        files["leg00B-capture.stderr.log"] = (
            _ctx_line(192, 200, 200)
            + 'kryprobe: telemetry {"v":1,"misses":'
            '{"unavailable":true}}\n')
        cell = self._cell(files)
        out = self._overlay(cell, self._judged(), self._c_leg(),
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("successor" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v3_async_leg_refuses(self):
        leg = dict(self._c_leg(), cls="P-ASYNC")
        cell = self._cell(self._c_files())
        out = self._overlay(cell, self._judged(), leg,
                            self._c_entry(), self._manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("async" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v3_floor_kernel_truth(self):
        cell = self._cell(self._c_files(misses=2, observed=400))
        judged = {"valid": True, "outcome": "valid", "reasons": [],
                  "driver": {"ops_total": 100}}
        out = CLI.apply_m1_ctx_overlay(
            cell, judged, self._c_leg(), self._c_entry(),
            self._manifest(3), kernel="6.12.111")
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_successor_epoch_is_per_leg(self):
        # The v3 truth equation applies to C/M legs only; R
        # keeps frozen exactness and non-pairs kinds (diags)
        # keep their frozen adjudication on any epoch.
        v3 = {"manifest_version": 3}
        v2 = {"manifest_version": 2}
        pairs = {"kind": "m1-pairs", "obs_a": "R", "obs_b": "M"}
        diag = {"kind": "m1-612-ctx"}
        self.assertTrue(CLI._successor_leg(v3, {"side": "B"}, pairs))
        self.assertFalse(CLI._successor_leg(v3, {"side": "A"}, pairs))
        self.assertFalse(CLI._successor_leg(v3, {"side": "B"}, diag))
        self.assertFalse(CLI._successor_leg(v2, {"side": "B"}, pairs))

    def _m_files(self, misses=2, observed=200):
        files = {"leg00B-report.workload-json": json.dumps(
            _workload_doc(observed))}
        stderr = _ctx_line(1, observed, observed)
        if misses is not None:
            stderr += _miss_line(9, misses)
        files["leg00B-capture.stderr.log"] = stderr
        files["leg00B-driver.csv.summary.json"] = json.dumps(
            {"ops_total": 100})
        return files

    def _m_leg(self):
        return {"leg_id": "leg00B", "side": "B", "mode": "aggregation",
                "cls": "P-4K", "driver": "skcipher",
                "workload": "single", "bulk": False, "threads": 2}

    def _m_entry(self):
        return {"kind": "m1-pairs", "obs_a": "R", "obs_b": "M"}

    def _m_manifest(self, version):
        doc = {"manifest_version": version,
               "workloads": {"single": {"expected_rows": 1}}}
        if version == 3:
            doc["global"] = {"expected_programs": 9}
        return doc

    def test_v3_m_leg_consistent_valid(self):
        cell = self._cell(self._m_files())
        out = self._overlay(cell, self._judged(), self._m_leg(),
                            self._m_entry(), self._m_manifest(3))
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_v3_m_leg_equation_off_invalid(self):
        cell = self._cell(self._m_files(misses=5))
        out = self._overlay(cell, self._judged(), self._m_leg(),
                            self._m_entry(), self._m_manifest(3))
        self.assertFalse(out["valid"])
        self.assertTrue(any("successor" in r for r in out["reasons"]),
                        out["reasons"])

    def test_v2_m_leg_ignores_successor_equation(self):
        cell = self._cell(self._m_files(misses=5))
        out = self._overlay(cell, self._judged(), self._m_leg(),
                            self._m_entry(), self._m_manifest(2))
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_v3_full_chain_supersedes_frozen_counts(self):
        # The frozen per-op gate (repro /tmp/repro_frozen_gate.py)
        # rejects this successor-consistent leg; the v3 chain
        # judges it by the truth equation instead.
        files = self._c_files()
        report = json.loads(files["leg00B-report.json"])
        # Missy per-op rows (99/99 vs ops 100) with a
        # reconciled aggregate sum (99 + 99 + 2 == 200).
        report["observations"] = [
            obs for obs in report["observations"]
            if obs["backend_payload"].get("row") != "totals"
        ] + [obs for obs in report["observations"]
             if obs["backend_payload"].get("row") == "totals"]
        files["leg00B-report.json"] = json.dumps(report)
        files["leg00B-driver.csv.summary.json"] = json.dumps({
            "ops_total": 100, "ops_meas": 100, "rows_meas": 4,
            "rc": 0, "fails": 0, "late": 0, "paced": 0, "threads": 2,
            "meas_window_s": 30.0, "t_warm_start_ns": 0,
            "t_meas_start_ns": 10_000_000_000,
            "t_end_ns": 40_000_000_000})
        files["leg00B-driver-rc.txt"] = \
            "driver_rc=0\ndriver_timeout=0\n"
        files["leg00B-driver.csv"] = (
            "seq,phase,op,dt_ns\n0,meas,encrypt,5\n0,meas,decrypt,7\n"
            "1,meas,encrypt,5\n1,meas,decrypt,7\n")
        files["leg00B-capture-rc.txt"] = "capture_rc=0\n"
        cell = self._cell(files)
        judged = CLI.judge_leg(cell, self._c_leg(), "7.0.14",
                               (10.0, 30.0), successor=True)
        judged = CLI.apply_m1_ctx_overlay(
            cell, judged, self._c_leg(), self._c_entry(),
            self._manifest(3), kernel="7.0.14")
        self.assertTrue(judged["valid"], judged.get("reasons"))


if __name__ == "__main__":
    unittest.main()
