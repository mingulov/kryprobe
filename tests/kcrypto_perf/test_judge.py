#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the T14 perf judge hardening (P9 round-1 A-N5/N6/N7).

A nonzero driver exit, an unreaped/timed-out host run, a
staged-pin mismatch against the sealed bytes, a shortened
measurement window, and a non-alternating pair order must all
FAIL — never ride a consistent seal to PASS. ``verify`` must
judge into an explicit ``--out-dir`` instead of rewriting the
sealed evidence (O-N9). Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_judge.py'
"""

import hashlib
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

WINDOWS = (10.0, 30.0)


def _t0():
    return 1_000_000_000_000


def _summary(ops=4, warm_s=10.0, meas_s=30.0, rc=0, fails=0,
             late=0, paced=0, threads=1, bulk=False):
    t0 = _t0()
    t_meas = t0 + int(warm_s * 1e9)
    t_end = t_meas + int(meas_s * 1e9)
    return {"ops_total": ops, "ops_meas": ops, "rows_meas": 2 * ops,
            "class": "skcipher", "size": 64,
            "t_warm_start_ns": t0, "t_meas_start_ns": t_meas,
            "t_end_ns": t_end, "meas_window_s": meas_s,
            "bulk": bulk, "paced": paced, "threads": threads,
            "offered": ops, "late": late, "fails": fails, "rc": rc,
            "timed_out": False}


def _csv(ops=4):
    lines = ["seq,phase,op,dt_ns"]
    for seq in range(ops):
        lines.append(f"{seq},meas,encrypt,1000")
        lines.append(f"{seq},meas,decrypt,2000")
    return "\n".join(lines) + "\n"


def _leg_dict(leg_id="leg00A", side="A", mode="disabled", bulk=0,
              threads=1):
    return {"leg_id": leg_id, "side": side, "mode": mode, "cls": "P-64",
            "driver": "skcipher", "size": 64, "workload": "flat",
            "paced": 0, "bulk": bulk, "threads": threads}


def _write_leg(cell, leg_id, summary, csv_text="",
               driver_rc=0, driver_timeout=0):
    legs = Path(cell) / "legs"
    legs.mkdir(parents=True, exist_ok=True)
    (legs / f"{leg_id}-driver.csv.summary.json").write_text(
        json.dumps(summary))
    (legs / f"{leg_id}-driver.csv").write_text(
        csv_text if csv_text else _csv(summary["ops_meas"]))
    (legs / f"{leg_id}-driver-rc.txt").write_text(
        f"driver_rc={driver_rc}\ndriver_timeout={driver_timeout}\n")


def _quiet_report(calls=0):
    counters = [{"name": name, "value": 0}
                for name in CLI.kparsers.LOSS_COUNTERS]
    return {"observations": [{"backend_payload":
                              {"row": "totals",
                               "counts": {"calls": calls, "errors": 0,
                                          "ok": calls, "queued": 0}}}],
            "coverage": {"aggregate_counts": {"counters": counters},
                         "detailed_events": {"counters": []}},
            "verdict": {"status": "partial"}}


def _receipt(wait_exit=0, timed_out=False, reaped=True, vng_exit=0,
             remaining=None, preexisting=True):
    if remaining is None:
        remaining = {}
    return {"process": {"wait": {"exit": wait_exit,
                                "timed_out": timed_out},
                        "stop": {"vng_exit": vng_exit, "reaped": reaped,
                                 "remaining_owned_qemu": remaining},
                        "vng_exit": vng_exit, "reaped": reaped},
            "cleanup": {"remaining_owned_qemu": remaining,
                        "preexisting_qemu_unchanged": preexisting}}


def _sealed_cell(tmp, name="cell-A", manifest_sha="MANIFEST",
                 receipt=None, kryprobe_bytes=b"fake-kryprobe",
                 kryprobe_pin=None, legs=2):
    """Minimal sealed cell: quiet + N disabled legs, consistent pins."""
    cell = Path(tmp) / name
    (cell / "legs").mkdir(parents=True)
    (cell / "quiet-report.json").write_text(
        json.dumps(_quiet_report(0)))
    rows = []
    for idx in range(legs):
        leg_id = f"leg{idx // 2:02d}{'A' if idx % 2 == 0 else 'B'}"
        _write_leg(cell, leg_id, _summary())
        rows.append("\t".join(
            [leg_id, "A" if idx % 2 == 0 else "B", "disabled", "P-64",
             "skcipher", "64", "flat", "0", "0", "1"]))
    (cell / "legs.tsv").write_text("\n".join(rows) + "\n")
    (cell / "kryprobe").write_bytes(kryprobe_bytes)
    if kryprobe_pin is None:
        kryprobe_pin = hashlib.sha256(kryprobe_bytes).hexdigest()
    (cell / "stage.json").write_text(json.dumps(
        {"kind": "set", "set": "S", "diag": None, "kernel": "7.0.14",
         "manifest_sha256": manifest_sha,
         "sha256": {"kryprobe": kryprobe_pin,
                    "kcrypto_fixture.ko": "none",
                    "validity.py": "unshipped-judge-pin"}}))
    (cell / "environment.txt").write_text(
        f"ko=\nkryprobe={hashlib.sha256(kryprobe_bytes).hexdigest()}\n")
    (cell / "host-receipt.json").write_text(
        json.dumps(receipt if receipt is not None else _receipt()))
    (cell / "done.txt").write_text("step=done\n")
    (cell / "legs-done.txt").write_text(f"legs_done={legs}\n")
    names = ["quiet-report.json", "legs.tsv", "kryprobe", "stage.json",
             "environment.txt", "host-receipt.json", "done.txt",
             "legs-done.txt"]
    for idx in range(legs):
        leg_id = f"leg{idx // 2:02d}{'A' if idx % 2 == 0 else 'B'}"
        names += [f"legs/{leg_id}-driver.csv.summary.json",
                  f"legs/{leg_id}-driver.csv",
                  f"legs/{leg_id}-driver-rc.txt"]
    CLI.krecept.seal_artifacts(cell, names, writers_done=True)
    return cell


def _manifest(sha="MANIFEST"):
    return {"_manifest_sha256": sha,
            "global": {"warmup_s": 10.0, "measure_s": 30.0}}


class DriverExitTests(unittest.TestCase):
    def test_actual_driver_exit_9_invalid_despite_summary_rc_0(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = Path(tmp) / "cell"
            _write_leg(cell, "leg00A", _summary(rc=0), driver_rc=9)
            got = CLI.judge_leg(cell, _leg_dict(), "7.0.14", WINDOWS)
        self.assertFalse(got["valid"])
        self.assertTrue(any("driver_rc" in r for r in got["reasons"]),
                        got["reasons"])

    def test_driver_timeout_invalid(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = Path(tmp) / "cell"
            _write_leg(cell, "leg00A", _summary(rc=0),
                       driver_rc=0, driver_timeout=1)
            got = CLI.judge_leg(cell, _leg_dict(), "7.0.14", WINDOWS)
        self.assertFalse(got["valid"])

    def test_bulk_leg_driver_exit_nonzero_invalid(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = Path(tmp) / "cell"
            _write_leg(cell, "leg05B", _summary(rc=0, bulk=True),
                       driver_rc=5)
            leg = _leg_dict("leg05B", "B", bulk=1)
            got = CLI.judge_leg(cell, leg, "7.0.14", WINDOWS)
        self.assertFalse(got["valid"])
        self.assertTrue(any("driver_rc" in r for r in got["reasons"]),
                        got["reasons"])

    def test_clean_disabled_leg_valid(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = Path(tmp) / "cell"
            _write_leg(cell, "leg00A", _summary())
            got = CLI.judge_leg(cell, _leg_dict(), "7.0.14", WINDOWS)
        self.assertTrue(got["valid"], got.get("reasons"))


class TimingGateTests(unittest.TestCase):
    def test_zero_warm_one_second_window_invalid(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = Path(tmp) / "cell"
            _write_leg(cell, "leg00A",
                       _summary(warm_s=0.0, meas_s=1.0))
            got = CLI.judge_leg(cell, _leg_dict(), "7.0.14", WINDOWS)
        self.assertFalse(got["valid"])
        self.assertTrue(any("window" in r or "warm" in r
                            for r in got["reasons"]),
                        got["reasons"])

    def test_sealed_like_windows_valid(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = Path(tmp) / "cell"
            _write_leg(cell, "leg00A",
                       _summary(warm_s=10.0001, meas_s=30.0855))
            got = CLI.judge_leg(cell, _leg_dict(), "7.0.14", WINDOWS)
        self.assertTrue(got["valid"], got.get("reasons"))


class HostReceiptGateTests(unittest.TestCase):
    def test_timeout_unreaped_nonzero_host_fails_cell(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = _sealed_cell(
                tmp, receipt=_receipt(wait_exit=137, timed_out=True,
                                      reaped=False, vng_exit=137))
            got = CLI.verify_cell(cell, _manifest())
        self.assertTrue(got["errors"], "timed-out host must fail")

    def test_clean_host_receipt_passes_cell(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = _sealed_cell(tmp)
            got = CLI.verify_cell(cell, _manifest())
        self.assertEqual(got.get("errors"), [])
        self.assertTrue(all(leg["valid"] for leg in got["legs"]))


def _sealed_names(cell: Path) -> list:
    """Names listed in a sealed cell's SHA256SUMS manifest."""
    return [line.split("  ")[1]
            for line in (cell / "SHA256SUMS").read_text().splitlines()]


class PinGateTests(unittest.TestCase):
    def test_missing_mandatory_artifact_file_fails_cell(self):
        # P9R2A-N01: a removed binary must FAIL even when the
        # remaining bytes re-seal consistently — only the named
        # unshipped pre-repair validity.py pin is unverifiable.
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = _sealed_cell(tmp)
            (cell / "kryprobe").unlink()
            names = [name for name in _sealed_names(cell)
                     if name != "kryprobe"]
            CLI.krecept.seal_artifacts(cell, names, writers_done=True)
            got = CLI.verify_cell(cell, _manifest())
        self.assertTrue(got["seal_ok"], "re-seal must hold")
        self.assertTrue(got["errors"], "missing binary must fail")
        self.assertTrue(any("kryprobe" in err
                            for err in got["errors"]),
                        got["errors"])

    def test_missing_mandatory_pin_key_fails_cell(self):
        # P9R2A-N01: a removed pin row must FAIL just like a
        # removed file — mandatory pin keys are enforced, not
        # skipped when absent.
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = _sealed_cell(tmp)
            stage = json.loads((cell / "stage.json").read_text())
            del stage["sha256"]["kryprobe"]
            (cell / "stage.json").write_text(json.dumps(stage))
            CLI.krecept.seal_artifacts(cell, _sealed_names(cell),
                                       writers_done=True)
            got = CLI.verify_cell(cell, _manifest())
        self.assertTrue(got["seal_ok"], "re-seal must hold")
        self.assertTrue(got["errors"], "missing pin key must fail")
        self.assertTrue(any("kryprobe" in err
                            for err in got["errors"]),
                        got["errors"])

    def test_pin_mismatch_fails_cell_despite_consistent_seal(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = _sealed_cell(tmp, kryprobe_bytes=b"mutated-bytes",
                                kryprobe_pin="0" * 64)
            got = CLI.verify_cell(cell, _manifest())
        self.assertTrue(got["errors"], "pin mismatch must fail")
        self.assertTrue(any("pin" in err.lower()
                            for err in got["errors"]),
                        got["errors"])

    def test_unshipped_pin_file_recorded_not_fatal(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            cell = _sealed_cell(tmp)
            got = CLI.verify_cell(cell, _manifest())
        self.assertEqual(got.get("errors"), [])
        self.assertIn("validity.py",
                      got.get("pin_check", {}).get("unverifiable", []))


class AlternationTests(unittest.TestCase):
    def _verdict(self, leg_id, side, order):
        return {"legs": [{"leg_id": leg_id, "side": side,
                          "bulk": 0, "valid": True, "reasons": [],
                          "order": order,
                          "stats": {"throughput": 100.0, "p50_ns": 1,
                                    "p99_ns": 2}}]}

    def test_all_AB_order_invalid_on_odd_pair(self):
        pair00 = CLI.form_pairs(
            [self._verdict("leg00A", "A", 0),
             self._verdict("leg00B", "B", 1)])
        pair01 = CLI.form_pairs(
            [self._verdict("leg01A", "A", 2),
             self._verdict("leg01B", "B", 3)])
        self.assertTrue(pair00[0]["valid"], pair00[0].get("reasons"))
        self.assertFalse(pair01[0]["valid"],
                         "pair leg01 must start with B")
        self.assertTrue(any("alternat" in r for r in pair01[0]["reasons"]),
                        pair01[0]["reasons"])

    def test_alternating_pairs_valid(self):
        pairs = CLI.form_pairs(
            [self._verdict("leg00A", "A", 0),
             self._verdict("leg00B", "B", 1),
             self._verdict("leg01B", "B", 2),
             self._verdict("leg01A", "A", 3)])
        self.assertEqual(len(pairs), 2)
        self.assertTrue(all(pair["valid"] for pair in pairs),
                        [pair.get("reasons") for pair in pairs])


class OutDirTests(unittest.TestCase):
    def test_verify_writes_to_out_dir_leaving_evidence_untouched(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            tmp = Path(tmp)
            ev = tmp / "evidence"
            ev.mkdir()
            manifest_path = tmp / "cells.json"
            manifest_path.write_text(json.dumps({
                "$schema": "kryprobe-perf-campaign/v1",
                "campaign": "test", "manifest_version": 1,
                "frozen_utc": "2026-09-29", "freeze_rule": "test",
                "budgets": {"B1_throughput_ratio_min": 0.95,
                            "B2_p99_ratio_max": 1.10},
                "global": {"kernels": ["7.0.14"],
                           "vng": {"7.0.14": "v7.0.14"},
                           "warmup_s": 10.0, "measure_s": 30.0,
                           "capture_s": 50, "settle_s": 5,
                           "quiet_s": 5, "pairs_per_set": 5,
                           "max_attempted_pairs": 6,
                           "guest_cpus": 4, "guest_memory": "4G",
                           "detail_cap": 100000},
                "classes": {"P-64": {"driver": "skcipher",
                                     "size": 64}},
                "modes": {"disabled": {}, "aggregation": {}},
                "sets": [{"id": "S", "class": "P-64",
                          "mode": "aggregation", "kernel": "7.0.14",
                          "workload": "flat", "budgeted": False}],
                "diagnostics": []}))
            sha = CLI.kmanifest.manifest_sha256(manifest_path)
            cell = _sealed_cell(ev, name="cell-A", manifest_sha=sha)
            lock_a = tmp / "a.lock"
            lock_b = tmp / "b.lock"
            lock_a.write_text("a")
            lock_b.write_text("b")
            (cell / "spawn.json").write_text(json.dumps(
                {"lock_paths": [str(lock_a), str(lock_b)]}))
            sums = CLI.krecept.seal_artifacts(
                cell,
                [line.split("  ")[1]
                 for line in (cell / "SHA256SUMS").read_text()
                 .splitlines()] + ["spawn.json"],
                writers_done=True)
            self.assertIn("spawn.json", sums)
            out = tmp / "out"
            rc = CLI.main(["verify", "--manifest", str(manifest_path),
                           "--evidence-dir", str(ev),
                           "--out-dir", str(out)])
            self.assertIn(rc, (0, 1))
            self.assertTrue((out / "verdicts" / "cell-A.json").is_file())
            self.assertTrue((out / "campaign.json").is_file())
            self.assertFalse((ev / "verdicts").exists())
            self.assertFalse((ev / "campaign.json").exists())

    def test_verify_rejects_out_dir_inside_evidence_dir(self):
        # P9R2O-N6: an --out-dir inside --evidence-dir would
        # write judgments into the sealed tree; fail closed.
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            tmp = Path(tmp)
            ev = tmp / "evidence"
            ev.mkdir()
            manifest_path = tmp / "cells.json"
            manifest_path.write_text(json.dumps({
                "$schema": "kryprobe-perf-campaign/v1",
                "campaign": "test", "manifest_version": 1,
                "frozen_utc": "2026-09-29", "freeze_rule": "test",
                "budgets": {"B1_throughput_ratio_min": 0.95,
                            "B2_p99_ratio_max": 1.10},
                "global": {"kernels": ["7.0.14"],
                           "vng": {"7.0.14": "v7.0.14"},
                           "warmup_s": 10.0, "measure_s": 30.0,
                           "capture_s": 50, "settle_s": 5,
                           "quiet_s": 5, "pairs_per_set": 5,
                           "max_attempted_pairs": 6,
                           "guest_cpus": 4, "guest_memory": "4G",
                           "detail_cap": 100000},
                "classes": {"P-64": {"driver": "skcipher",
                                     "size": 64}},
                "modes": {"disabled": {}, "aggregation": {}},
                "sets": [{"id": "S", "class": "P-64",
                          "mode": "aggregation", "kernel": "7.0.14",
                          "workload": "flat", "budgeted": False}],
                "diagnostics": []}))
            rc = CLI.main(["verify", "--manifest", str(manifest_path),
                           "--evidence-dir", str(ev),
                           "--out-dir", str(ev / "out")])
            self.assertEqual(rc, 2)

    def test_verify_refuses_implicit_in_place(self):
        with tempfile.TemporaryDirectory(prefix="t14j") as tmp:
            tmp = Path(tmp)
            ev = tmp / "evidence"
            ev.mkdir()
            manifest_path = tmp / "cells.json"
            manifest_path.write_text("{}")
            rc = CLI.main(["verify", "--manifest", str(manifest_path),
                           "--evidence-dir", str(ev)])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
