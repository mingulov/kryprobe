#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for demo manifest strictness + artifact binding (Task 1).

Standard library only; no guests, no privilege, no qemu. A skipped
body, an unknown schema/field, or a mismatched artifact hash refuses
loudly: no receipt, no QMP mutation, no PASS.

Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_qemu_demo -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import receipts, reconcile  # noqa: E402


def minimal_manifest() -> dict:
    """Smallest valid inputs/v1 manifest (one image, harness cell only)."""
    return {
        "$schema": "kcrypto.qemu-demo.inputs/v1",
        "campaign": "kcrypto-demo-qemu",
        "manifest_version": 1,
        "frozen_utc": "2026-09-29T23:38:33Z",
        "freeze_rule": "frozen before the first demo guest boot",
        "product": {
            "repo_sha": "2540b491ce0747e7efc2b63dc1d5c2eef62b9223",
            "cli_sha": "c9ae31bd5517700404392311d68643aede4936ae47c41db39caef8800fe24ec2",
            "bpf_agg_sha": "c76fd83f532869b6d86f7189af0d4575d78b27137f5b77873b3043fe9eba97f5",
            "bpf_lc_sha": "7244932d0c8828919770b32ba1555b1a74eccd674de326a6173d062dd0f150cb",
        },
        "qemu": {
            "path": "/usr/bin/qemu-system-x86_64",
            "version": "10.2.1",
            "sha256": "00" * 32,
        },
        "images": [
            {
                "id": "img-7014-base",
                "kernel": "7.0.14",
                "vmlinuz": "/frozen/vmlinuz-7.0.14",
                "vmlinuz_sha256": "11" * 32,
                "config_sha256": "22" * 32,
                "initramfs": "/frozen/initramfs-7014.cpio",
                "initramfs_sha256": "33" * 32,
                "rootfs": "/frozen/root-7014.raw",
                "rootfs_sha256": "44" * 32,
                "rootfs_format": "raw",
                "cpu": {"model": "host", "flags": ["aes"]},
                "devices": [],
            }
        ],
        "cells": [
            {
                "id": "T01-harness",
                "title": "owned cold boot, no observer, no workload",
                "image": "img-7014-base",
                "workload": {"kind": "cold-boot-no-observer"},
                "limits": {"timeout_s": 180},
                "expected_evidence": ["spawn.json", "console.log", "stop.json"],
            }
        ],
    }


def write_manifest(tmp: Path, manifest: dict) -> Path:
    path = tmp / "INPUTS.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


class ManifestTests(unittest.TestCase):
    def test_valid_manifest_loads_and_binds_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), minimal_manifest())
            loaded = receipts.load_manifest(path)
            self.assertEqual(loaded["_manifest_sha256"], receipts.sha256_file(path))
            self.assertEqual(loaded["cells"][0]["id"], "T01-harness")

    def test_unknown_schema_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["$schema"] = "kcrypto.qemu-demo.inputs/v9"
            with self.assertRaisesRegex(receipts.InputError, "unknown manifest schema"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_unknown_top_level_field_refuses(self):
        # Unknown custody-affecting fields fail closed, never ignored.
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["extra_sauce"] = "ignored?"
            with self.assertRaisesRegex(receipts.InputError, "unknown manifest keys"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_unknown_product_field_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["product"]["mystery_pin"] = "00" * 32
            with self.assertRaisesRegex(receipts.InputError, "unknown product keys"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_unknown_cell_id_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["cells"][0]["id"] = "D99"
            with self.assertRaisesRegex(receipts.InputError, "unknown cell id"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_cell_with_unknown_image_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["cells"][0]["image"] = "img-nope"
            with self.assertRaisesRegex(receipts.InputError, "unknown image"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_bool_version_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["manifest_version"] = True
            with self.assertRaisesRegex(receipts.InputError, "manifest_version"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_unbudgeted_timeout_refuses(self):
        # Only the plan's three bounded budgets exist (180/300/1500).
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["cells"][0]["limits"]["timeout_s"] = 3600
            with self.assertRaisesRegex(receipts.InputError, "timeout_s"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))

    def test_duplicate_cell_id_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = minimal_manifest()
            manifest["cells"].append(dict(manifest["cells"][0]))
            with self.assertRaisesRegex(receipts.InputError, "duplicate cell id"):
                receipts.load_manifest(write_manifest(Path(tmp), manifest))


class ArtifactTests(unittest.TestCase):
    def test_rejects_unknown_artifact_hash(self):
        # Staged bytes must equal the frozen pin; a mismatch raises and
        # writes no receipt (no QMP mutation, no PASS input).
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp) / "kryprobe"
            staged.write_bytes(b"some-bytes")
            with self.assertRaisesRegex(receipts.ArtifactError, "hash mismatch"):
                receipts.verify_artifact(staged, "00" * 32)
            self.assertEqual(list(Path(tmp).glob("*.json")), [])

    def test_missing_artifact_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(receipts.ArtifactError, "missing artifact"):
                receipts.verify_artifact(Path(tmp) / "absent", "00" * 32)

    def test_matching_artifact_returns_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp) / "kryprobe"
            staged.write_bytes(b"some-bytes")
            digest = receipts.verify_artifact(staged, receipts.sha256_file(staged))
            self.assertEqual(digest, receipts.sha256_file(staged))

    def test_seal_requires_writers_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.log").write_text("x\n")
            with self.assertRaisesRegex(ValueError, "writers_done"):
                receipts.seal_artifacts(Path(tmp), ["a.log"], writers_done=False)

    def test_seal_missing_artifact_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(FileNotFoundError, "seal artifact missing"):
                receipts.seal_artifacts(Path(tmp), ["absent.log"], writers_done=True)


class SkipTests(unittest.TestCase):
    def test_skip_body_is_not_run(self):
        # A skipped body (expected declared, actual absent) is FAIL, not
        # a pass and not a silent NOT_RUN.
        receipt = {
            "$schema": "kcrypto.qemu-demo.cell/v1",
            "cell_id": "D01",
            "verdict": "RUN",
            "process": {"exit": 0, "timed_out": False, "reaped": True},
            "cleanup": {"remaining_owned": {}, "preexisting_unchanged": True},
            "custody": {"hashes_unchanged": True},
            "expected_body": {"ops": 300},
            "actual_body": None,
        }
        judged = reconcile.reconcile_cell(receipt)
        self.assertEqual(judged["verdict"], "FAIL")
        self.assertTrue(any("actual_body" in r for r in judged["reasons"]))


if __name__ == "__main__":
    unittest.main()
