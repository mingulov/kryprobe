#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the P8/T13 receipt reconciler.

Standard library only; no guests, no privilege. Every gate is
pinned by a causal counterexample: the receipt that must fail is
constructed, and the failure reason is asserted. Run from the
product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_reconcile.py'
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_campaign import reconcile  # noqa: E402

PINS = {"kryprobe": "aaa", "kcrypto.bpf.o": "bbb", "oracle": "ccc"}


def passing_receipt() -> dict:
    return {
        "cell_id": "R02-dmcrypt",
        "portion_id": "R02-7014",
        "process": {"exit": 0, "timed_out": False, "reaped": True},
        "cleanup": {"remaining_owned": {}, "preexisting_unchanged": True},
        "custody": {"hashes_unchanged": True, "flush_ok": True},
        "observation": {"expected": {"ops": 64}, "actual": {"ops": 64}},
        "checks": {"ledger_exact": True, "zero_ring_drops": True},
        "oracle_failed": [],
        "required_bodies": ["r02-write", "r02-read"],
        "actual_bodies": ["r02-write", "r02-read"],
        "expected_body": {"ops": [1, 2, 3]},
        "actual_body": {"ops": [1, 2, 3]},
        "pins": dict(PINS),
        "executed": dict(PINS),
        "cleanup_required": ["mapping", "loop", "netns"],
        "cleanup_done": ["mapping", "loop", "netns"],
    }


class ReconcileTests(unittest.TestCase):
    def test_clean_receipt_passes(self):
        verdict = reconcile.verify_receipt(passing_receipt())
        self.assertEqual(verdict["verdict"], "PASS")
        self.assertEqual(verdict["reasons"], [])

    def test_timeout_cannot_pass(self):
        rec = passing_receipt()
        rec["process"]["timed_out"] = True
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("timed out" in r for r in verdict["reasons"]))

    def test_exit_zero_skip_cannot_pass(self):
        # Worker exited 0 but produced nothing: the expected/actual
        # body equality fails closed (an exit-0 skip is not a pass).
        rec = passing_receipt()
        rec["actual_body"] = {"ops": []}
        rec["observation"]["actual"] = {"ops": 0}
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("body" in r for r in verdict["reasons"]))

    def test_foreign_denominator_cannot_pass(self):
        # Actual bodies include a foreign body the manifest never
        # required: totals must not absorb it.
        rec = passing_receipt()
        rec["actual_bodies"] = ["r02-write", "r02-read", "foreign-xfrm"]
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("foreign-xfrm" in r for r in verdict["reasons"]))

    def test_absent_required_body_cannot_pass(self):
        rec = passing_receipt()
        rec["actual_bodies"] = ["r02-write"]
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("r02-read" in r for r in verdict["reasons"]))

    def test_body_count_mismatch_cannot_pass(self):
        rec = passing_receipt()
        rec["actual_body"] = {"ops": [1, 2]}
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("expected_body" in r for r in verdict["reasons"]))

    def test_stale_executable_cannot_pass(self):
        # Executed bytes differ from the staged pin: the proof is
        # for other bytes, so it cannot pass.
        rec = passing_receipt()
        rec["executed"]["kryprobe"] = "zzz"
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("kryprobe" in r for r in verdict["reasons"]))

    def test_missing_artifact_pin_cannot_pass(self):
        rec = passing_receipt()
        del rec["executed"]["oracle"]
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("oracle" in r for r in verdict["reasons"]))

    def test_missing_cleanup_cannot_pass(self):
        rec = passing_receipt()
        rec["cleanup_done"] = ["mapping", "loop"]
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("netns" in r for r in verdict["reasons"]))

    def test_remaining_owned_resources_cannot_pass(self):
        rec = passing_receipt()
        rec["cleanup"]["remaining_owned"] = {"4242": {"args": ["qemu-system-x86_64"]}}
        self.assertEqual(reconcile.verify_receipt(rec)["verdict"], "FAIL")

    def test_final_flush_failure_cannot_pass(self):
        rec = passing_receipt()
        rec["custody"]["flush_ok"] = False
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("flush" in r for r in verdict["reasons"]))

    def test_changed_hashes_cannot_pass(self):
        rec = passing_receipt()
        rec["custody"]["hashes_unchanged"] = False
        self.assertEqual(reconcile.verify_receipt(rec)["verdict"], "FAIL")

    def test_false_oracle_check_cannot_pass(self):
        rec = passing_receipt()
        rec["checks"]["zero_ring_drops"] = False
        verdict = reconcile.verify_receipt(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("zero_ring_drops" in r for r in verdict["reasons"]))

    def test_omitted_loss_dimensions_cannot_pass(self):
        rec = passing_receipt()
        rec["observation"]["omitted_loss_dimensions"] = ["ring"]
        self.assertEqual(reconcile.verify_receipt(rec)["verdict"], "FAIL")

    def test_not_run_needs_reason_and_control(self):
        self.assertEqual(
            reconcile.verify_receipt({"verdict": "NOT_RUN"})["verdict"], "FAIL"
        )
        rec = {"verdict": "NOT_RUN", "reason": "no dm-crypt", "positive_control": "R01-det"}
        self.assertEqual(reconcile.verify_receipt(rec)["verdict"], "NOT_RUN")

    def test_supported_refusal_needs_reason_and_control(self):
        rec = {"verdict": "SUPPORTED_REFUSAL"}
        self.assertEqual(reconcile.verify_receipt(rec)["verdict"], "FAIL")
        rec = {
            "verdict": "SUPPORTED_REFUSAL",
            "reason": "fsession predates 6.12",
            "positive_control": "R01-floor-612-aggregate",
        }
        self.assertEqual(reconcile.verify_receipt(rec)["verdict"], "SUPPORTED_REFUSAL")

    def test_verify_receipt_file_is_offline(self):
        # verify reads one receipt file and writes nothing beside it.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "host-receipt.json"
            path.write_text(json.dumps(passing_receipt()))
            verdict = reconcile.verify_receipt_file(path)
            self.assertEqual(verdict["verdict"], "PASS")
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["host-receipt.json"])

    def test_campaign_reconcile_passes_complete_set(self):
        receipts = [passing_receipt()]
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014"], receipts=receipts
        )
        self.assertEqual(summary["verdict"], "PASS")
        self.assertEqual(summary["per_portion"], {"R02-7014": "PASS"})

    def test_campaign_reconcile_refuses_duplicate_portion(self):
        receipts = [passing_receipt(), passing_receipt()]
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014"], receipts=receipts
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertTrue(any("duplicate" in r for r in summary["reasons"]))

    def test_campaign_reconcile_refuses_mixed_pins(self):
        first, second = passing_receipt(), passing_receipt()
        second["portion_id"] = "R02-726"
        second["executed"]["kryprobe"] = "different-bytes"
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014", "R02-726"], receipts=[first, second]
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertTrue(any("mixed pins" in r for r in summary["reasons"]))

    def test_campaign_reconcile_reports_missing_portion(self):
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014", "R02-726"], receipts=[passing_receipt()]
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertTrue(any("R02-726" in r for r in summary["reasons"]))

    def test_campaign_reconcile_uniform_subset(self):
        # Per-portion artifacts (guest config, per-kernel module)
        # legitimately vary; the uniform CLI/BPF/fixture/oracle
        # pins must still match exactly.
        first, second = passing_receipt(), passing_receipt()
        second["portion_id"] = "R02-726"
        first["pins"]["guest-config"] = "cfg7014"
        first["executed"]["guest-config"] = "cfg7014"
        second["pins"]["guest-config"] = "cfg726"
        second["executed"]["guest-config"] = "cfg726"
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014", "R02-726"],
            receipts=[first, second],
            uniform_pins=["kryprobe", "kcrypto.bpf.o", "oracle"],
        )
        self.assertEqual(summary["verdict"], "PASS")
        # A consistent-but-different CLI build across portions:
        # each receipt is internally consistent, the campaign
        # uniformity gate must still refuse.
        second["pins"]["kryprobe"] = "different-bytes"
        second["executed"]["kryprobe"] = "different-bytes"
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014", "R02-726"],
            receipts=[first, second],
            uniform_pins=["kryprobe", "kcrypto.bpf.o", "oracle"],
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertTrue(any("mixed pins" in r for r in summary["reasons"]))

    def test_campaign_reconcile_propagates_failing_portion(self):
        rec = passing_receipt()
        rec["process"]["exit"] = 1
        summary = reconcile.reconcile_campaign(
            required_portions=["R02-7014"], receipts=[rec]
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertEqual(summary["per_portion"], {"R02-7014": "FAIL"})


if __name__ == "__main__":
    unittest.main()
