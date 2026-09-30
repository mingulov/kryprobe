#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the static evidence timeline (attempt 4, Task 5).

The timeline renders sealed receipts into SVG. Every edge must
carry a known label plus its run ID (validated before render);
per-boot clocks must never be aligned across cells; missing
receipts render as explicit unknown rows, never gaps.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import reconcile, timeline  # noqa: E402


def make_cell(parent: Path, name: str, receipt: dict | None,
              marks: str = "") -> Path:
    cell_dir = parent / name
    cell_dir.mkdir(parents=True)
    if receipt is not None:
        (cell_dir / f"cell-{receipt['cell_id']}.json").write_text(
            json.dumps(receipt))
    (cell_dir / "console.log").write_text(marks)
    return cell_dir


RUN_RECEIPT = {
    "$schema": "kcrypto.qemu-demo.cell/v1",
    "run_id": "run9",
    "cell_id": "D01",
    "verdict": "RUN",
    "selected_driver": "cbc-aes-aesni",
    "checks": {"all_status_ok": True, "kryprobe_present": True},
}

MARKS = (
    'DEMO:MARK {"name": "INIT-READY", "ts_mono": 1.0}\n'
    'DEMO:MARK {"name": "WORKLOAD-DONE", "ts_mono": 9.0}\n'
)


class TimelineTests(unittest.TestCase):
    def test_edges_carry_labels_and_run_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            edges, rows = timeline.collect_run(root)
        judged = reconcile.timeline_edges(edges)
        self.assertTrue(judged["ok"], judged)
        self.assertTrue(all(edge["run_id"] == "run9" for edge in edges))
        by_pair = {(e["frm"], e["to"]): e["label"] for e in edges}
        self.assertEqual(by_pair[("requested", "selected")], "observed")
        self.assertEqual(by_pair[("entered", "queued")], "unknown")
        self.assertEqual(by_pair[("completed", "reported")], "reference")
        self.assertIn("D01", rows)

    def test_no_inferred_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            edges, _ = timeline.collect_run(root)
        self.assertNotIn("inferred", {edge["label"] for edge in edges})

    def test_missing_receipt_is_unknown_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_cell(root, "D0X", None, MARKS)
            edges, rows = timeline.collect_run(root)
        self.assertEqual(rows["D0X"]["verdict"], "UNKNOWN")
        self.assertTrue(all(edge["label"] == "unknown" for edge in edges))

    def test_probe_dirs_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe = root / "probe-base"
            probe.mkdir()
            (probe / "probe.json").write_text("{}")
            (probe / "console.log").write_text(MARKS)
            make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            _, rows = timeline.collect_run(root)
        self.assertNotIn("probe-base", rows)
        self.assertIn("D01", rows)

    def test_unsupported_cell_is_unknown_edge(self):
        receipt = {"run_id": "run9", "cell_id": "D06",
                   "verdict": "UNSUPPORTED", "reason": "x01 absent"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_cell(root, "D06", receipt, "")
            edges, rows = timeline.collect_run(root)
        self.assertEqual(rows["D06"]["verdict"], "UNSUPPORTED")
        self.assertEqual(edges[0]["label"], "unknown")

    def test_svg_states_per_boot_clocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            edges, rows = timeline.collect_run(root)
            svg = timeline.render_svg("run9", edges, rows)
        self.assertIn("per-boot guest clocks", svg)
        self.assertIn("not measured", svg)
        self.assertIn("replay", svg)
        self.assertIn("run9", svg)
        self.assertIn("1.0–9.0s guest", svg)


def make_sealed(cell_dir: Path) -> None:
    (cell_dir / "SHA256SUMS").write_text("seal\n")


def make_log(root: Path, name: str, verdict: str) -> None:
    (root / name).write_text(json.dumps(
        {"cell": "D01", "verdict": verdict, "reasons": []}))


class TimelineV2Tests(unittest.TestCase):
    """R6 RED: verdict-aware rows, evidence layers, unsealed marking."""

    def test_v1_default_unchanged(self):
        # V1 rendering stays byte-stable (sealed p10a4 SVG reproduces).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            edges, rows = timeline.collect_run(root)
        self.assertEqual(rows["D01"]["verdict"], "RUN")
        self.assertTrue(all("layer" not in edge for edge in edges))

    def test_v2_rows_show_run_log_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            passing = make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            make_sealed(passing)
            make_log(root, "D01.log", "PASS")
            failing = make_cell(root, "D02", dict(RUN_RECEIPT), MARKS)
            make_sealed(failing)
            make_log(root, "D02.log", "FAIL")
            _, rows = timeline.collect_run(root, v2=True)
        self.assertEqual(rows["D01"]["verdict"], "PASS")
        self.assertEqual(rows["D02"]["verdict"], "FAIL")

    def test_v2_unsealed_history_marked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            torn = dict(RUN_RECEIPT)
            torn["checks"] = {"console": False}
            cell_dir = make_cell(root, "D01-rerun1", torn, MARKS)
            self.assertFalse((cell_dir / "SHA256SUMS").exists())
            (root / "D01-rerun1.log").write_text(
                "run: seal refused: seal artifact missing\n")
            edges, rows = timeline.collect_run(root, v2=True)
            svg = timeline.render_svg("run9", edges, rows, v2=True)
        self.assertEqual(rows["D01-rerun1"]["verdict"], "FAIL")
        self.assertFalse(rows["D01-rerun1"]["sealed"])
        self.assertIn("unsealed-history", svg)

    def test_v2_edges_carry_evidence_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cell_dir = make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            make_sealed(cell_dir)
            make_log(root, "D01.log", "PASS")
            edges, _ = timeline.collect_run(root, v2=True)
        by_pair = {(e["frm"], e["to"]): (e["label"], e["layer"])
                   for e in edges}
        self.assertEqual(by_pair[("requested", "selected")],
                         ("observed", "guest-probe"))
        self.assertEqual(by_pair[("selected", "entered")],
                         ("unknown", "none"))
        self.assertEqual(by_pair[("returned", "completed")],
                         ("observed", "caller-ledger"))
        self.assertEqual(by_pair[("completed", "reported")],
                         ("reference", "product-report"))

    def test_v2_selected_entered_never_observed(self):
        # A6: caller-ledger success proves neither provider-body
        # entry nor product completion; the edge stays unknown.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cell_dir = make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            make_sealed(cell_dir)
            make_log(root, "D01.log", "PASS")
            edges, _ = timeline.collect_run(root, v2=True)
        entered = [e for e in edges
                   if (e["frm"], e["to"]) == ("selected", "entered")]
        self.assertEqual(len(entered), 1)
        self.assertEqual(entered[0]["label"], "unknown")

    def test_v2_svg_shows_verdicts_and_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cell_dir = make_cell(root, "D01", dict(RUN_RECEIPT), MARKS)
            make_sealed(cell_dir)
            make_log(root, "D01.log", "PASS")
            edges, rows = timeline.collect_run(root, v2=True)
            svg = timeline.render_svg("run9", edges, rows, v2=True)
        self.assertIn("[PASS]", svg)
        self.assertIn("caller-ledger", svg)
        self.assertIn("run ID", svg)
        self.assertIn("replay", svg)


if __name__ == "__main__":
    unittest.main()
