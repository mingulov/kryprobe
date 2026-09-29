#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the T14 frozen perf-manifest loader (stdlib only).

Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_manifest.py'
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
    "kcrypto_perf_manifest",
    str(ROOT / "scripts" / "kcrypto_perf" / "manifest.py"))
MANIFEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(MANIFEST)


def minimal_manifest(**over):
    doc = {
        "$schema": "kryprobe-perf-campaign/v1",
        "campaign": "kcrypto-t14",
        "manifest_version": 1,
        "frozen_utc": "2026-09-29T00:00:00Z",
        "freeze_rule": "frozen before the first T14 sampling boot",
        "budgets": {"B1_throughput_ratio_min": 0.95,
                    "B2_p99_ratio_max": 1.10},
        "global": {"kernels": ["7.0.14"],
                   "vng": {"7.0.14": "v7.0.14"},
                   "warmup_s": 10, "measure_s": 30, "capture_s": 50,
                   "settle_s": 5, "quiet_s": 5, "pairs_per_set": 5,
                   "max_attempted_pairs": 8, "guest_cpus": 4,
                   "guest_memory": "4G", "detail_cap": 100000},
        "classes": {"P-64": {"driver": "skcipher", "size": 64}},
        "modes": {"aggregation": {"profile": "api-returns"}},
        "sets": [{"id": "perf-P-64-agg-7014", "class": "P-64",
                  "mode": "aggregation", "kernel": "7.0.14",
                  "workload": "flat", "budgeted": False}],
        "diagnostics": [],
    }
    doc.update(over)
    return doc


def write_manifest(doc):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(doc, tmp, indent=2)
    tmp.close()
    return Path(tmp.name)


class LoaderTests(unittest.TestCase):
    def test_minimal_loads(self):
        loaded = MANIFEST.load_manifest(write_manifest(minimal_manifest()))
        self.assertEqual(loaded["campaign"], "kcrypto-t14")
        self.assertIn("_manifest_sha256", loaded)
        self.assertEqual(len(loaded["_manifest_sha256"]), 64)

    def test_seal_binds_bytes(self):
        path = write_manifest(minimal_manifest())
        first = MANIFEST.load_manifest(path)["_manifest_sha256"]
        raw = path.read_bytes() + b"\n"
        path.write_bytes(raw)
        second = MANIFEST.load_manifest(path)["_manifest_sha256"]
        self.assertNotEqual(first, second)

    def test_bad_schema_refused(self):
        with self.assertRaises(MANIFEST.InputError):
            MANIFEST.load_manifest(write_manifest(minimal_manifest(
                **{"$schema": "kryprobe-consumer-campaign/v1"})))

    def test_missing_key_refused(self):
        doc = minimal_manifest()
        del doc["budgets"]
        with self.assertRaises(MANIFEST.InputError):
            MANIFEST.load_manifest(write_manifest(doc))

    def test_duplicate_set_ids_refused(self):
        doc = minimal_manifest()
        doc["sets"] = [doc["sets"][0], dict(doc["sets"][0])]
        with self.assertRaises(MANIFEST.InputError):
            MANIFEST.load_manifest(write_manifest(doc))

    def test_unknown_kernel_refused(self):
        doc = minimal_manifest()
        doc["sets"][0]["kernel"] = "5.15.0"
        with self.assertRaises(MANIFEST.InputError):
            MANIFEST.load_manifest(write_manifest(doc))

    def test_unknown_class_refused(self):
        doc = minimal_manifest()
        doc["sets"][0]["class"] = "P-NOPE"
        with self.assertRaises(MANIFEST.InputError):
            MANIFEST.load_manifest(write_manifest(doc))

    def test_not_json_refused(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.write("{nope")
        tmp.close()
        with self.assertRaises(MANIFEST.InputError):
            MANIFEST.load_manifest(Path(tmp.name))


class FrozenManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = MANIFEST.load_manifest(
            HERE / "cells.json")

    def test_pair_set_count(self):
        pair_sets = [s for s in self.manifest["sets"]
                     if s.get("kind", "pairs") == "pairs"]
        # 7.0.14: 5 flat x agg + 5 flat x det + 3 paced det
        # 7.2.6: 5 flat x agg + 5 flat x det
        # 6.12.111 floor: 2 agg (4K, 1M)
        self.assertEqual(len(pair_sets), 25)

    def test_budgeted_sets(self):
        budgeted = sorted(s["id"] for s in self.manifest["sets"]
                          if s.get("budgeted"))
        self.assertEqual(budgeted, [
            "perf-P-1M-agg-7014", "perf-P-1M-agg-726",
            "perf-P-4K-agg-7014", "perf-P-4K-agg-726"])

    def test_async_paced_is_cost_only(self):
        cost = [s for s in self.manifest["sets"]
                if s.get("kind") == "cost-only"]
        self.assertEqual(len(cost), 1)
        self.assertEqual(cost[0]["id"], "perf-P-ASYNC-det-paced-7014")

    def test_stack_mode_not_run(self):
        self.assertEqual(
            self.manifest["modes"]["stack-sampling"]["status"], "NOT_RUN")

    def test_budgets_frozen(self):
        self.assertEqual(
            self.manifest["budgets"]["B1_throughput_ratio_min"], 0.95)
        self.assertEqual(
            self.manifest["budgets"]["B2_p99_ratio_max"], 1.10)


if __name__ == "__main__":
    unittest.main()
