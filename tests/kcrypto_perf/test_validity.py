#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the T14 leg/pair/set validity judges (stdlib only).

Validity rules mirror the frozen P9 manifest: exact driver/product
equivalence per kernel and class, zero unexpected loss, rc in
{0,3}, quiet boots. Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_validity.py'
"""

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_validity",
    str(ROOT / "scripts" / "kcrypto_perf" / "validity.py"))
VALIDITY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(VALIDITY)


def zero_loss(destroy_skip=1):
    return {"ktot_gap": 0, "ring_drops": 0, "overflow_identities": 0,
            "predrop_cfg_fail": 0, "predrop_fret_fail": 0,
            "predrop_arg_null": 0, "predrop_chase_fail": 0,
            "predrop_name_fail": 0, "predrop_destroy_skip": destroy_skip,
            "predrop_spare_6": 0, "predrop_spare_7": 0}


def afalg_report(enc, dec, alloc=1, loss=None, queued=0):
    def row(op, calls):
        return {"calls": calls, "ok": calls, "errors": 0, "queued": queued,
                "bytes": calls * 64}
    return {
        "agg": {("skcipher", "encrypt", "cbc-aes-aesni"): row("e", enc),
                ("skcipher", "decrypt", "cbc-aes-aesni"): row("d", dec)},
        "alloc_rows": [{"calls": alloc, "ok": alloc, "errors": 0,
                        "queued": 0, "algorithm": "cbc(aes)"}],
        "totals": {"calls": enc + dec + alloc, "errors": 0,
                   "ok": enc + dec + alloc, "queued": queued},
        "loss": loss if loss is not None else zero_loss(),
        "verdict": {"status": "partial"}, "who": []}


def driver_summary(ops_total, ops_meas=0, cls="skcipher"):
    return {"ops_total": ops_total, "ops_meas": ops_meas or ops_total,
            "rows_meas": 2 * (ops_meas or ops_total), "class": cls,
            "rc": 0, "timed_out": False}


class AfalgValidityTests(unittest.TestCase):
    def test_exact_match_valid(self):
        got = VALIDITY.check_leg_agg(
            afalg_report(92391, 92391), driver_summary(92391),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertTrue(got["valid"], got["reasons"])
        self.assertEqual(got["outcome"], "valid")

    def test_off_by_one_invalid(self):
        got = VALIDITY.check_leg_agg(
            afalg_report(92390, 92391), driver_summary(92391),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])
        self.assertTrue(any("encrypt" in r for r in got["reasons"]))

    def test_dec_mismatch_invalid(self):
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 99), driver_summary(100),
            kernel="7.2.6", cls="P-4K", capture_rc=0)
        self.assertFalse(got["valid"])

    def test_alloc_mismatch_invalid(self):
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100, alloc=2), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])

    def test_loss_invalid(self):
        loss = zero_loss()
        loss["ring_drops"] = 1
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100, loss=loss), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])
        self.assertTrue(any("ring_drops" in r for r in got["reasons"]))

    def test_predrop_unexpected_invalid(self):
        loss = zero_loss()
        loss["predrop_fret_fail"] = 2
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100, loss=loss), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])

    def test_ktot_gap_invalid(self):
        loss = zero_loss()
        loss["ktot_gap"] = 7
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100, loss=loss), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])

    def test_destroy_skip_pinned(self):
        loss = zero_loss(destroy_skip=2)
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100, loss=loss), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])

    def test_probe_alloc_unpinned_destroy(self):
        report = afalg_report(80000, 80000, alloc=20,
                              loss=zero_loss(destroy_skip=7))
        got = VALIDITY.check_leg_agg(
            report, driver_summary(80000),
            kernel="7.0.14", cls="P-64", capture_rc=3,
            expected_alloc=20, pin_destroy=False)
        self.assertTrue(got["valid"], got["reasons"])

    def test_bad_capture_rc_invalid(self):
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=1)
        self.assertFalse(got["valid"])

    def test_driver_timeout_invalid(self):
        summary = driver_summary(100)
        summary["timed_out"] = True
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100), summary,
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])

    def test_queued_forbidden_afalg(self):
        got = VALIDITY.check_leg_agg(
            afalg_report(100, 100, queued=5), driver_summary(100),
            kernel="7.0.14", cls="P-64", capture_rc=3)
        self.assertFalse(got["valid"])


class FloorValidityTests(unittest.TestCase):
    def _floor_report(self, arm_calls=100):
        def row(driver, op):
            return {"calls": arm_calls, "ok": arm_calls, "errors": 0,
                    "queued": 0, "bytes": arm_calls * 4096}
        return {
            "agg": {("skcipher", "encrypt", "cbc-aes-aesni"):
                    row("cbc-aes-aesni", "encrypt"),
                    ("skcipher", "encrypt", "__cbc-aes-aesni"):
                    row("__cbc-aes-aesni", "encrypt"),
                    ("skcipher", "decrypt", "cbc-aes-aesni"):
                    row("cbc-aes-aesni", "decrypt"),
                    ("skcipher", "decrypt", "__cbc-aes-aesni"):
                    row("__cbc-aes-aesni", "decrypt")},
            "alloc_rows": [
                {"calls": 1, "ok": 1, "errors": 0, "queued": 0,
                 "algorithm": "cbc(aes)"},
                {"calls": 1, "ok": 1, "errors": 0, "queued": 0,
                 "algorithm": "cryptd(__cbc-aes-aesni)"}],
            "totals": {"calls": 4 * arm_calls + 2, "errors": 0,
                       "ok": 4 * arm_calls + 2, "queued": 0},
            "loss": zero_loss(), "verdict": {"status": "partial"},
            "who": []}

    def test_nested_arms_valid(self):
        got = VALIDITY.check_leg_agg(
            self._floor_report(84071), driver_summary(84071),
            kernel="6.12.111", cls="P-4K", capture_rc=3)
        self.assertTrue(got["valid"], got["reasons"])

    def test_split_violation_invalid(self):
        report = self._floor_report(100)
        report["agg"][("skcipher", "encrypt", "__cbc-aes-aesni")] = {
            "calls": 99, "ok": 99, "errors": 0, "queued": 0, "bytes": 0}
        got = VALIDITY.check_leg_agg(
            report, driver_summary(100),
            kernel="6.12.111", cls="P-4K", capture_rc=3)
        self.assertFalse(got["valid"])

    def test_floor_destroy_skip_unpinned_per_manifest(self):
        # The frozen manifest's floor equivalence names no
        # destroy pin (cells.json equivalence.floor_afalg);
        # the observed floor counter (3) is recorded, never
        # judged. P9R1O-N2 harness-defect repair.
        report = self._floor_report(100)
        report["loss"] = zero_loss(destroy_skip=3)
        got = VALIDITY.check_leg_agg(
            report, driver_summary(100),
            kernel="6.12.111", cls="P-4K", capture_rc=3)
        self.assertTrue(got["valid"], got["reasons"])


class AsyncValidityTests(unittest.TestCase):
    def _async_report(self, gos=30):
        return {
            "agg": {("skcipher", "encrypt", "kxc-async"): {
                "calls": gos, "ok": 0, "errors": 0, "queued": gos,
                "bytes": gos * 16}},
            "alloc_rows": [{"calls": gos, "ok": gos, "errors": 0,
                            "queued": 0, "algorithm": "kxc"}],
            "totals": {"calls": 2 * gos, "errors": 0, "ok": gos,
                       "queued": gos},
            "loss": zero_loss(destroy_skip=gos),
            "verdict": {"status": "partial"}, "who": []}

    def test_async_exact_valid(self):
        got = VALIDITY.check_leg_agg(
            self._async_report(30), driver_summary(30, cls="async"),
            kernel="7.0.14", cls="P-ASYNC", capture_rc=3)
        self.assertTrue(got["valid"], got["reasons"])

    def test_async_ok_must_be_zero(self):
        report = self._async_report(30)
        key = ("skcipher", "encrypt", "kxc-async")
        report["agg"][key] = dict(report["agg"][key], ok=30, queued=0)
        got = VALIDITY.check_leg_agg(
            report, driver_summary(30, cls="async"),
            kernel="7.0.14", cls="P-ASYNC", capture_rc=3)
        self.assertFalse(got["valid"])


class DetailsValidityTests(unittest.TestCase):
    def _lc(self, obs, emitted=None, truncated=False, unfinished=0,
            loss=None, terminals=None):
        n = emitted if emitted is not None else obs
        return {"observations": obs,
                "terminals": terminals or {"sync": obs},
                "receipt": {"verdict": "partial", "truncated": truncated,
                            "admitted": n, "emitted": n,
                            "unfinished": unfinished,
                            "loss": loss if loss is not None else {}}}

    def test_clean_details_valid(self):
        got = VALIDITY.check_leg_details(
            self._lc(216), expected_calls=216, cls="P-1M")
        self.assertEqual(got["outcome"], "valid")
        self.assertTrue(got["valid"])

    def test_truncated_is_envelope_not_valid(self):
        got = VALIDITY.check_leg_details(
            self._lc(100000, emitted=100001, truncated=True,
                     loss={"driver.omitted": 1}),
            expected_calls=1400000, cls="P-64")
        self.assertEqual(got["outcome"], "truncated")
        self.assertFalse(got["valid"])

    def test_short_count_invalid(self):
        got = VALIDITY.check_leg_details(
            self._lc(215), expected_calls=216, cls="P-1M")
        self.assertEqual(got["outcome"], "invalid")
        self.assertFalse(got["valid"])

    def test_loss_invalid(self):
        got = VALIDITY.check_leg_details(
            self._lc(216, loss={"kernel.disabled": 1}),
            expected_calls=216, cls="P-1M")
        self.assertFalse(got["valid"])

    def test_async_details_envelope_only(self):
        got = VALIDITY.check_leg_details(
            self._lc(10, unfinished=10, terminals={"unknown": 10}),
            expected_calls=10, cls="P-ASYNC")
        self.assertEqual(got["outcome"], "envelope")
        self.assertFalse(got["valid"])


class QuietPairSetTests(unittest.TestCase):
    def test_quiet_zero_valid(self):
        self.assertTrue(VALIDITY.check_quiet({"calls": 0})["valid"])

    def test_quiet_nonzero_invalid(self):
        got = VALIDITY.check_quiet({"calls": 3})
        self.assertFalse(got["valid"])

    def test_pair_needs_both_legs(self):
        self.assertTrue(VALIDITY.check_pair(True, True)["valid"])
        self.assertFalse(VALIDITY.check_pair(True, False)["valid"])
        self.assertFalse(VALIDITY.check_pair(False, False)["valid"])

    def test_set_needs_five(self):
        self.assertTrue(VALIDITY.check_set([True] * 5)["qualified"])
        self.assertFalse(VALIDITY.check_set([True] * 4)["qualified"])
        self.assertTrue(VALIDITY.check_set([True] * 6)["qualified"])
        mixed = [True, True, True, True, False, True]
        self.assertTrue(VALIDITY.check_set(mixed)["qualified"])
        self.assertEqual(VALIDITY.check_set(mixed)["valid_pairs"], 5)


if __name__ == "__main__":
    unittest.main()
