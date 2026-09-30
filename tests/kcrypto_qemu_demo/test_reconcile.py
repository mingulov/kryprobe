#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for demo cell reconciliation (Task 1).

Standard library only; no guests, no privilege, no qemu. The
reconciler is the only PASS authority: timeout, nonzero exit,
unreaped worker, remaining owned resources, changed preexisting
resources, changed hashes, count deltas, failed oracle checks and
one-sided bodies all fail. Declared NOT_RUN/UNSUPPORTED pass only
with a reason plus a named positive control. A required cell that
did not run fails the campaign — never a hidden NOT_RUN behind PASS.
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import reconcile  # noqa: E402


def clean_receipt(cell_id: str = "T01-harness") -> dict:
    return {
        "$schema": "kcrypto.qemu-demo.cell/v1",
        "run_id": "p10a1-test",
        "cell_id": cell_id,
        "verdict": "RUN",
        "process": {"exit": 0, "timed_out": False, "reaped": True},
        "cleanup": {"remaining_owned": {}, "preexisting_unchanged": True},
        "custody": {"hashes_unchanged": True},
        "observation": {"expected": 1, "actual": 1},
        "checks": {"console_has_init_ready": True},
    }


class ReconcileTests(unittest.TestCase):
    def test_clean_receipt_passes(self):
        judged = reconcile.reconcile_cell(clean_receipt())
        self.assertEqual(judged["verdict"], "PASS")
        self.assertEqual(judged["reasons"], [])

    def test_timeout_cannot_pass(self):
        receipt = clean_receipt()
        receipt["process"]["timed_out"] = True
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("timed out" in r for r in judged["reasons"]))

    def test_nonzero_exit_fails(self):
        receipt = clean_receipt()
        receipt["process"]["exit"] = 1
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_unreaped_fails(self):
        receipt = clean_receipt()
        receipt["process"]["reaped"] = False
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_remaining_owned_fails(self):
        receipt = clean_receipt()
        receipt["cleanup"]["remaining_owned"] = {"4242": {"args": ["qemu"]}}
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_preexisting_changed_fails(self):
        receipt = clean_receipt()
        receipt["cleanup"]["preexisting_unchanged"] = False
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_hashes_changed_fails(self):
        receipt = clean_receipt()
        receipt["custody"]["hashes_unchanged"] = False
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_expected_actual_mismatch_fails(self):
        receipt = clean_receipt()
        receipt["observation"]["actual"] = 2
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "FAIL")

    def test_failed_oracle_check_fails(self):
        receipt = clean_receipt()
        receipt["checks"]["console_has_init_ready"] = False
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("console_has_init_ready" in r for r in judged["reasons"]))

    def test_named_oracle_failure_fails(self):
        receipt = clean_receipt()
        receipt["oracle_failed"] = ["zero-loss"]
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_wrong_schema_fails(self):
        receipt = clean_receipt()
        receipt["$schema"] = "kcrypto.qemu-demo.cell/v9"
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_not_run_without_reason_fails(self):
        receipt = {"verdict": "NOT_RUN", "cell_id": "D04"}
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "FAIL")

    def test_not_run_with_reason_and_control_is_not_run(self):
        receipt = {
            "verdict": "NOT_RUN",
            "cell_id": "D04",
            "reason": "queue adapter unavailable (R2 gate open)",
            "positive_control": "T01-harness cold boot",
        }
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "NOT_RUN")

    def test_unsupported_with_reason_and_control_is_unsupported(self):
        receipt = {
            "verdict": "UNSUPPORTED",
            "cell_id": "D06",
            "reason": "no real fallback trigger qualified on 7.0.14",
            "positive_control": "X01 controlled threshold fixture",
        }
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "UNSUPPORTED")

    def test_body_mismatch_fails(self):
        receipt = clean_receipt()
        receipt["expected_body"] = {"ops": 300}
        receipt["actual_body"] = {"ops": 299}
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_stale_pin_fails(self):
        receipt = clean_receipt()
        receipt["pins"] = {"kryprobe": "aa"}
        receipt["executed"] = {"kryprobe": "bb"}
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("stale" in r for r in judged["reasons"]))

    def test_missing_cleanup_fails(self):
        receipt = clean_receipt()
        receipt["cleanup_required"] = ["overlay-removed", "qmp-closed"]
        receipt["cleanup_done"] = ["qmp-closed"]
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")

    def test_failed_flush_fails(self):
        receipt = clean_receipt()
        receipt["custody"]["flush_ok"] = False
        self.assertEqual(reconcile.reconcile_cell(receipt)["verdict"], "FAIL")


class CampaignTests(unittest.TestCase):
    def test_hidden_not_run_behind_pass_fails(self):
        judged = reconcile.reconcile_campaign(
            ["T01-harness", "D01"],
            [
                clean_receipt("T01-harness"),
                {
                    "verdict": "NOT_RUN",
                    "cell_id": "D01",
                    "reason": "workload not implemented",
                    "positive_control": "T01-harness cold boot",
                },
            ],
        )
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertEqual(judged["per_cell"]["T01-harness"], "PASS")
        self.assertEqual(judged["per_cell"]["D01"], "NOT_RUN")

    def test_duplicate_cell_refuses(self):
        judged = reconcile.reconcile_campaign(
            ["T01-harness"],
            [clean_receipt("T01-harness"), clean_receipt("T01-harness")],
        )
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("duplicate" in r for r in judged["reasons"]))

    def test_missing_required_cell_fails(self):
        judged = reconcile.reconcile_campaign(["T01-harness", "D01"], [clean_receipt("T01-harness")])
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("D01" in r for r in judged["reasons"]))

    def test_mixed_product_pins_fail(self):
        first = clean_receipt("T01-harness")
        first["pins"] = {"kryprobe": "aa"}
        first["executed"] = {"kryprobe": "aa"}
        second = clean_receipt("D01")
        second["pins"] = {"kryprobe": "aa"}
        second["executed"] = {"kryprobe": "bb"}
        judged = reconcile.reconcile_campaign(
            ["T01-harness", "D01"], [first, second], uniform_pins=["kryprobe"]
        )
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("mixed pins" in r for r in judged["reasons"]))

    def test_uniform_product_with_varied_images_passes(self):
        # Per-cell guest images legitimately vary; the product pins must not.
        first = clean_receipt("T01-harness")
        first["pins"] = {"kryprobe": "aa", "vmlinuz": "img7014"}
        first["executed"] = {"kryprobe": "aa", "vmlinuz": "img7014"}
        second = clean_receipt("D01")
        second["pins"] = {"kryprobe": "aa", "vmlinuz": "img726"}
        second["executed"] = {"kryprobe": "aa", "vmlinuz": "img726"}
        judged = reconcile.reconcile_campaign(
            ["T01-harness", "D01"], [first, second], uniform_pins=["kryprobe"]
        )
        self.assertEqual(judged["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
