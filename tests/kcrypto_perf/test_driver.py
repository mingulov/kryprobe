#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host behavior tests for the T14 perf workload driver.

Runs short AF_ALG bursts on the build host (needs
CONFIG_CRYPTO_USER_API; fails loudly without it — never a silent
skip) plus ledger-format checks. The async class needs the kernel
fixture and is format-tested against a fake control file only;
its guest semantics are proved by the campaign's own validity
gates. Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_driver.py'
"""

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DRIVER = ROOT / "tests" / "fixtures" / "kcrypto_perf.py"


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
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
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
