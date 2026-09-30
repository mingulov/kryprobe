#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host oracle tests for D01-D08 false-pass cases (Tasks 2-5, RED-first).

Standard library only; no guests, no privilege, no qemu. Each test
feeds the pure oracle helper a fixture that a naive implementation
would mislabel, and asserts the helper fails closed:

- Task 2 (D01-D03): registry != usage, retained != fresh, I/O bytes
  and API calls are different populations.
- Task 3 (D04-D06): equal driver strings do not identify a device,
  selection without queue proof is not offload, removal never
  implies retry/failover, an unrelated child is not fallback.
- Task 4 (D07): unlock requires attach-ready, late attach preserves
  the unobserved interval, exactly one observer survives handoff.
- Task 5 (D08): slow-sink loss stays visible, soak caps never
  restart silently, timeline arrows need labels + run IDs.
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import reconcile  # noqa: E402


class SelectionTests(unittest.TestCase):
    def test_registry_entry_is_not_usage(self):
        registry = ["cbc-aes-aesni", "cbc-aes-generic", "xts-aes-aesni"]
        used = ["cbc-aes-aesni"]
        verdict = reconcile.provider_usage(registry, used)
        self.assertEqual(verdict["used"], ["cbc-aes-aesni"])
        # Registered but unused providers stay "available", never "used".
        self.assertEqual(
            sorted(verdict["available_only"]), ["cbc-aes-generic", "xts-aes-aesni"]
        )

    def test_cached_transform_is_not_fresh_selection(self):
        events = [
            {"alloc_id": "tfm-1", "reused": False},
            {"alloc_id": "tfm-1", "reused": True},
            {"alloc_id": "tfm-2", "reused": False},
        ]
        verdict = reconcile.fresh_vs_retained(events)
        self.assertEqual(sorted(verdict["fresh_ids"]), ["tfm-1", "tfm-2"])
        self.assertEqual(verdict["retained_ids"], ["tfm-1"])
        # A retained handle must not count as a fresh selection.
        self.assertEqual(len(verdict["fresh_ids"]), 2)

    def test_io_bytes_are_not_api_call_count(self):
        # One 4 KiB I/O split into four 1 KiB API calls: bytes and
        # calls reconcile in different populations.
        counts = reconcile.split_counts(4096, [1024, 1024, 1024, 1024])
        self.assertEqual(counts, {"io_bytes": 4096, "api_calls": 4})
        self.assertNotEqual(counts["io_bytes"], counts["api_calls"])


class DeviceTests(unittest.TestCase):
    def test_same_driver_does_not_identify_device(self):
        rows = [
            {"driver": "virtio-crypto", "dev": "crypto0"},
            {"driver": "virtio-crypto", "dev": "crypto1"},
        ]
        verdict = reconcile.identify_device(rows, queue_rows=[])
        self.assertEqual(verdict["device"], "unknown")
        self.assertIn("same driver", verdict["reason"])

    def test_queue_proof_identifies_device(self):
        rows = [
            {"driver": "virtio-crypto", "dev": "crypto0"},
            {"driver": "virtio-crypto", "dev": "crypto1"},
        ]
        verdict = reconcile.identify_device(
            rows, queue_rows=[{"dev": "crypto1", "queue": 0}]
        )
        self.assertEqual(verdict["device"], "crypto1")

    def test_selected_without_queue_is_not_offload(self):
        self.assertFalse(reconcile.is_offload("virtio-crypto", queue_proof=None))
        self.assertFalse(
            reconcile.is_offload("virtio-crypto", queue_proof={"dev": "crypto0"})
        )
        self.assertTrue(
            reconcile.is_offload(
                "virtio-crypto",
                queue_proof={"dev": "crypto0", "queue": 0, "bound": True},
            )
        )

    def test_removed_device_does_not_imply_retry(self):
        verdict = reconcile.removal_outcome(
            {"dev": "crypto0", "quiesced": True, "qmp_event": True},
            {"driver": "cbc-aes-aesni", "errno": None},
        )
        self.assertFalse(verdict["implies_retry"])
        self.assertFalse(verdict["implies_failover"])
        self.assertEqual(verdict["observed"], "reselected:cbc-aes-aesni")

    def test_removal_without_quiesce_records_fault(self):
        verdict = reconcile.removal_outcome(
            {"dev": "crypto0", "quiesced": False, "qmp_event": True},
            {"driver": None, "errno": -5},
        )
        self.assertFalse(verdict["implies_retry"])
        self.assertIn("errno", verdict["observed"])

    def test_unrelated_child_is_not_fallback(self):
        verdict = reconcile.fallback_relation(
            parent_rows=[{"id": "p1", "driver": "parent"}],
            child_rows=[{"id": "c9", "driver": "child"}],
            proof=None,
        )
        self.assertEqual(verdict["relation"], "unknown")

    def test_proved_child_is_fallback(self):
        verdict = reconcile.fallback_relation(
            parent_rows=[{"id": "p1", "driver": "parent"}],
            child_rows=[{"id": "c1", "driver": "child"}],
            proof={"parent": "p1", "child": "c1", "bind": "request-token"},
        )
        self.assertEqual(verdict["relation"], "proved")

    def test_x01_threshold_oracle(self):
        expected = {512: "child", 1024: "child", 4096: "direct"}
        good = [
            {"size": 512, "path": "child", "ops": 100},
            {"size": 1024, "path": "child", "ops": 100},
            {"size": 4096, "path": "direct", "ops": 100},
        ]
        self.assertEqual(
            reconcile.check_x01_threshold(good, expected),
            {"verdict": True, "reasons": []},
        )
        bad = [
            {"size": 512, "path": "direct", "ops": 100},
            {"size": 1024, "path": "child", "ops": 100},
            {"size": 4096, "path": "direct", "ops": 100},
        ]
        judged = reconcile.check_x01_threshold(bad, expected)
        self.assertFalse(judged["verdict"])
        short = [
            {"size": 512, "path": "child", "ops": 99},
            {"size": 1024, "path": "child", "ops": 100},
            {"size": 4096, "path": "direct", "ops": 100},
        ]
        self.assertFalse(reconcile.check_x01_threshold(short, expected)["verdict"])


class BootTests(unittest.TestCase):
    def test_unlock_requires_attach_ready(self):
        self.assertTrue(reconcile.unlock_after_attach(100.0, 120.0))
        self.assertFalse(reconcile.unlock_after_attach(None, 120.0))
        self.assertFalse(reconcile.unlock_after_attach(130.0, 120.0))
        self.assertFalse(reconcile.unlock_after_attach(120.0, 120.0))

    def test_late_attach_preserves_unobserved_interval(self):
        gap = reconcile.unobserved_interval(boot_ts=0.0, attach_ts=90.0)
        self.assertEqual(gap["mark"], "UNOBSERVED")
        self.assertEqual((gap["start"], gap["end"]), (0.0, 90.0))

    def test_missing_attach_is_unbounded_unobserved(self):
        gap = reconcile.unobserved_interval(boot_ts=0.0, attach_ts=None)
        self.assertEqual(gap["mark"], "UNOBSERVED")
        self.assertFalse(gap["bounded"])

    def test_switch_root_preserves_one_observer(self):
        one = [{"pid": 100, "alive": True, "fds_preserved": True}]
        self.assertTrue(reconcile.single_observer(one))
        two = [
            {"pid": 100, "alive": True, "fds_preserved": True},
            {"pid": 101, "alive": True, "fds_preserved": True},
        ]
        self.assertFalse(reconcile.single_observer(two))
        dead = [{"pid": 100, "alive": False, "fds_preserved": True}]
        self.assertFalse(reconcile.single_observer(dead))
        closed = [{"pid": 100, "alive": True, "fds_preserved": False}]
        self.assertFalse(reconcile.single_observer(closed))


class SoakTests(unittest.TestCase):
    def test_slow_sink_loss_remains_visible(self):
        self.assertTrue(reconcile.loss_visible({"dropped": 0, "omitted": []}))
        self.assertTrue(reconcile.loss_visible({"dropped": 12, "omitted": []}))
        # Uncounted loss is not zero loss.
        self.assertFalse(reconcile.loss_visible({"omitted": []}))
        self.assertFalse(reconcile.loss_visible({"dropped": 0}))

    def test_soak_cap_does_not_restart_silently(self):
        good = [
            {"id": "w0", "capped": True, "reset": None},
            {"id": "w1", "capped": True, "reset": "explicit"},
        ]
        self.assertTrue(reconcile.soak_windows(good)["ok"])
        silent = [{"id": "w0", "capped": True, "reset": "silent"}]
        self.assertFalse(reconcile.soak_windows(silent)["ok"])
        uncapped = [{"id": "w0", "capped": False, "reset": None}]
        self.assertFalse(reconcile.soak_windows(uncapped)["ok"])

    def test_timeline_refuses_unproved_arrows(self):
        good = [
            {"frm": "requested", "to": "selected", "label": "observed", "run_id": "r1"},
            {"frm": "selected", "to": "queued", "label": "unknown", "run_id": "r1"},
        ]
        self.assertTrue(reconcile.timeline_edges(good)["ok"])
        unlabeled = [{"frm": "a", "to": "b", "run_id": "r1"}]
        self.assertFalse(reconcile.timeline_edges(unlabeled)["ok"])
        unbound = [{"frm": "a", "to": "b", "label": "observed"}]
        self.assertFalse(reconcile.timeline_edges(unbound)["ok"])
        wild = [{"frm": "a", "to": "b", "label": "proved", "run_id": "r1"}]
        self.assertFalse(reconcile.timeline_edges(wild)["ok"])


if __name__ == "__main__":
    unittest.main()
