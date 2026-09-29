#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the T14 perf statistics helpers (no guests, stdlib only).

Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_stats.py'
"""

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_stats", str(ROOT / "scripts" / "kcrypto_perf" / "stats.py"))
STATS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(STATS)


class PercentileTests(unittest.TestCase):
    def test_nearest_rank(self):
        vals = [1, 2, 3, 4, 5]
        self.assertEqual(STATS.percentile(vals, 50), 3)
        self.assertEqual(STATS.percentile(vals, 100), 5)
        self.assertEqual(STATS.percentile(vals, 1), 1)

    def test_p99(self):
        vals = list(range(1, 101))
        self.assertEqual(STATS.percentile(vals, 99), 99)
        self.assertEqual(STATS.percentile(vals, 50), 50)

    def test_single(self):
        self.assertEqual(STATS.percentile([42], 99), 42)

    def test_unsorted_input(self):
        self.assertEqual(STATS.percentile([5, 1, 4, 2, 3], 50), 3)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            STATS.percentile([], 50)

    def test_bad_p_raises(self):
        with self.assertRaises(ValueError):
            STATS.percentile([1, 2], 0)
        with self.assertRaises(ValueError):
            STATS.percentile([1, 2], 101)


class MedianTests(unittest.TestCase):
    def test_odd(self):
        self.assertEqual(STATS.median([3, 1, 2]), 2)

    def test_even(self):
        self.assertEqual(STATS.median([1, 2, 3, 4]), 2.5)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            STATS.median([])


class RoundtripTests(unittest.TestCase):
    def test_afalg_pairs_by_seq(self):
        rows = [(0, "meas", "encrypt", 100), (0, "meas", "decrypt", 50),
                (1, "meas", "encrypt", 120), (1, "meas", "decrypt", 60)]
        self.assertEqual(STATS.roundtrip_latencies(rows, "skcipher"),
                         [150, 180])

    def test_async_go_direct(self):
        rows = [(0, "meas", "go", 30000), (1, "meas", "go", 33000)]
        self.assertEqual(STATS.roundtrip_latencies(rows, "async"),
                         [30000, 33000])

    def test_unpaired_seq_raises(self):
        rows = [(0, "meas", "encrypt", 100)]
        with self.assertRaises(ValueError):
            STATS.roundtrip_latencies(rows, "skcipher")

    def test_duplicate_op_raises(self):
        rows = [(0, "meas", "encrypt", 100), (0, "meas", "encrypt", 50)]
        with self.assertRaises(ValueError):
            STATS.roundtrip_latencies(rows, "skcipher")

    def test_wrong_op_for_class_raises(self):
        rows = [(0, "meas", "go", 100)]
        with self.assertRaises(ValueError):
            STATS.roundtrip_latencies(rows, "skcipher")


class ThroughputTests(unittest.TestCase):
    def test_basic(self):
        self.assertAlmostEqual(STATS.throughput(30000, 30.0), 1000.0)

    def test_zero_window_raises(self):
        with self.assertRaises(ValueError):
            STATS.throughput(10, 0.0)


class SetVerdictTests(unittest.TestCase):
    def test_throughput_pass(self):
        ratios = [0.97, 0.98, 0.96, 0.99, 0.97]
        self.assertEqual(STATS.set_verdict(ratios, lo=0.95, hi=None), "PASS")

    def test_throughput_fail(self):
        ratios = [0.90, 0.91, 0.92, 0.93, 0.94]
        self.assertEqual(STATS.set_verdict(ratios, lo=0.95, hi=None), "FAIL")

    def test_one_outlier_still_passes(self):
        ratios = [0.96, 0.97, 0.90, 0.98, 0.97]
        self.assertEqual(STATS.set_verdict(ratios, lo=0.95, hi=None), "PASS")

    def test_two_outliers_inconclusive(self):
        ratios = [0.96, 0.97, 0.90, 0.91, 0.98]
        self.assertEqual(STATS.set_verdict(ratios, lo=0.95, hi=None),
                         "INCONCLUSIVE")

    def test_latency_pass(self):
        ratios = [1.02, 1.05, 1.03, 1.12, 1.04]
        self.assertEqual(STATS.set_verdict(ratios, lo=None, hi=1.10), "PASS")

    def test_latency_fail(self):
        ratios = [1.11, 1.15, 1.12, 1.20, 1.13]
        self.assertEqual(STATS.set_verdict(ratios, lo=None, hi=1.10), "FAIL")

    def test_median_inside_but_split_inconclusive(self):
        ratios = [1.01, 1.02, 1.30, 1.40, 1.03]
        self.assertEqual(STATS.set_verdict(ratios, lo=None, hi=1.10),
                         "INCONCLUSIVE")

    def test_fewer_than_five_inconclusive(self):
        self.assertEqual(STATS.set_verdict([0.97] * 4, lo=0.95, hi=None),
                         "INCONCLUSIVE")

    def test_empty_inconclusive(self):
        self.assertEqual(STATS.set_verdict([], lo=0.95, hi=None),
                         "INCONCLUSIVE")

    def test_spare_pairs_count(self):
        ratios = [0.97] * 7
        self.assertEqual(STATS.set_verdict(ratios, lo=0.95, hi=None), "PASS")

    def test_no_bounds_raises(self):
        with self.assertRaises(ValueError):
            STATS.set_verdict([1.0] * 5, lo=None, hi=None)


if __name__ == "__main__":
    unittest.main()
