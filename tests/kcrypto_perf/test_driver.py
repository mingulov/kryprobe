#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host behavior tests for the T14 perf workload driver.

Runs short AF_ALG bursts on the build host (needs
CONFIG_CRYPTO_USER_API; fails loudly without it — never a silent
skip) plus ledger-format checks. The AEAD burst asserts the
driver's loud ENOENT refusal on kernels without AF_ALG AEAD
instead of skipping. The async class needs the kernel
fixture and is format-tested against a fake control file only;
its guest semantics are proved by the campaign's own validity
gates. Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_driver.py'
"""

import csv
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DRIVER = ROOT / "tests" / "fixtures" / "kcrypto_perf.py"

_FIX_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_fixture", str(DRIVER))
FIXTURE = importlib.util.module_from_spec(_FIX_SPEC)
_FIX_SPEC.loader.exec_module(FIXTURE)


def run_driver(*args):
    tmp = Path(tempfile.mkdtemp(prefix="t14drv"))
    ledger = tmp / "ledger.csv"
    proc = subprocess.run(
        [sys.executable, str(DRIVER), *args, str(ledger)],
        capture_output=True, text=True, timeout=120)
    return proc, ledger


class DriverTests(unittest.TestCase):
    def test_skcipher_burst(self):
        proc, ledger = run_driver("skcipher", "64", "1", "0.5")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        summary = json.loads(
            Path(str(ledger) + ".summary.json").read_text())
        self.assertGreater(summary["ops_meas"], 100)
        self.assertEqual(summary["class"], "skcipher")
        self.assertEqual(summary["size"], 64)
        rows = list(csv.DictReader(ledger.read_text().splitlines()))
        self.assertGreater(len(rows), 100)
        self.assertEqual(rows[0]["op"], "encrypt")
        self.assertTrue(all(int(r["dt_ns"]) > 0 for r in rows[:50]))

    def test_aead_burst(self):
        proc, ledger = run_driver("aead", "1024", "1", "0.5")
        if proc.returncode != 0:
            # Honest denial on kernels without AF_ALG AEAD:
            # bind(("aead", "gcm(aes)")) raises ENOENT and the driver
            # fails loudly per contract. Only that exact refusal
            # signature passes here; anything else fails below.
            self.assertEqual(proc.returncode, 1)
            self.assertIn("driver failed:", proc.stderr)
            self.assertIn("[Errno 2] No such file or directory",
                          proc.stderr)
            return
        summary = json.loads(Path(str(ledger) + ".summary.json").read_text())
        self.assertGreater(summary["ops_meas"], 10)
        self.assertEqual(summary["size"], 1024)

    def test_bulk_has_no_rows(self):
        proc, ledger = run_driver("skcipher", "64", "1", "0.5", "--bulk")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        summary = json.loads(Path(str(ledger) + ".summary.json").read_text())
        self.assertTrue(summary["bulk"])
        self.assertGreater(summary["ops_meas"], 100)
        rows = list(csv.DictReader(ledger.read_text().splitlines()))
        self.assertEqual(rows, [])

    def test_bad_class_exits_2(self):
        proc, _ = run_driver("nope", "64", "1", "0.5")
        self.assertEqual(proc.returncode, 2)

    def test_threads_two(self):
        proc, ledger = run_driver("skcipher", "64", "1", "0.5", "--threads",
                                  "2")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        summary = json.loads(
            Path(str(ledger) + ".summary.json").read_text())
        self.assertEqual(summary["threads"], 2)
        self.assertGreater(summary["ops_meas"], 100)

    def test_async_threads_rejected(self):
        proc, _ = run_driver("async", "16", "0.5", "0.2", "--threads", "2")
        self.assertEqual(proc.returncode, 2)

    def test_paced_rate(self):
        proc, ledger = run_driver("skcipher", "64", "1", "0.5", "--paced",
                                  "200")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        summary = json.loads(
            Path(str(ledger) + ".summary.json").read_text())
        self.assertEqual(summary["paced"], 200)
        # 1.5 s at 200/s offers ~300 ops; allow scheduling slack.
        self.assertGreater(summary["ops_total"], 200)
        self.assertLess(summary["ops_total"], 400)

    def test_bulk_skcipher_reads_no_timestamps(self):
        # P9R1A-N8 repair (P9R2O-N6 scope note): the sealed
        # campaign's --bulk legs still paid three clock reads
        # per op inside roundtrip(); the repaired
        # roundtrip_bulk() method itself reads no timestamps
        # (asserted here). worker_loop still reads the clock
        # once per op for pacing/phase in both modes —
        # symmetric and harmless, but the no-clock guarantee
        # covers roundtrip_bulk only, not whole bulk legs.
        worker = FIXTURE.Skcipher(64)
        try:
            with mock.patch.object(
                    FIXTURE.time, "monotonic_ns",
                    side_effect=AssertionError("clock read")):
                calls = worker.roundtrip_bulk(7)
        finally:
            worker.close()
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(t0 == 0 and t1 == 0
                            for _, t0, t1, _ in calls))

    def test_bulk_worker_loop_uses_notimestamp_path(self):
        class Stub:
            def __init__(self):
                self.calls = 0
                self.bulk_calls = 0

            def roundtrip(self, seq):
                self.calls += 1
                return [("encrypt", 0, 1, 0), ("decrypt", 0, 1, 0)]

            def roundtrip_bulk(self, seq):
                self.bulk_calls += 1
                return [("encrypt", 0, 0, 0), ("decrypt", 0, 0, 0)]

        worker = Stub()
        shared = FIXTURE.Shared()
        now = time.monotonic_ns()
        FIXTURE.worker_loop(
            worker, {"paced": 0, "bulk": True}, shared,
            io.StringIO(), now, now, now + 20_000_000)
        self.assertGreater(worker.bulk_calls, 0)
        self.assertEqual(worker.calls, 0)

    def test_ledger_worker_loop_uses_timestamp_path(self):
        class Stub:
            def __init__(self):
                self.calls = 0
                self.bulk_calls = 0

            def roundtrip(self, seq):
                self.calls += 1
                return [("encrypt", 0, 1, 0), ("decrypt", 0, 1, 0)]

            def roundtrip_bulk(self, seq):
                self.bulk_calls += 1
                return [("encrypt", 0, 0, 0), ("decrypt", 0, 0, 0)]

        worker = Stub()
        shared = FIXTURE.Shared()
        now = time.monotonic_ns()
        FIXTURE.worker_loop(
            worker, {"paced": 0, "bulk": False}, shared,
            io.StringIO(), now, now, now + 20_000_000)
        self.assertGreater(worker.calls, 0)
        self.assertEqual(worker.bulk_calls, 0)

    def test_async_fake_control_format(self):
        tmp = Path(tempfile.mkdtemp(prefix="t14async"))
        ctl = tmp / "control"
        ctl.write_text("READY\n")
        ledger = tmp / "ledger.csv"
        proc = subprocess.run(
            [sys.executable, str(DRIVER), "async", "16", "0.5", "0.2",
             "--control", str(ctl), str(ledger)],
            capture_output=True, text=True, timeout=120)
        # A regular file accepts the PREPARE/GO writes; the driver
        # records rows in the committed format (guest semantics are
        # judged in-campaign, not here).
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        rows = list(csv.DictReader(ledger.read_text().splitlines()))
        self.assertGreater(len(rows), 0)
        self.assertTrue(all(r["op"] == "go" for r in rows))


if __name__ == "__main__":
    unittest.main()
