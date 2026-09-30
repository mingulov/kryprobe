#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the demo CLI surface (attempt 4).

The CLI script is not importable (hyphenated name), so these tests
drive it through subprocess with a fixture manifest. Only offline
paths are exercised (plan, unknown-cell refusal, reuse refusal,
the no-boot D06 UNSUPPORTED lane, offline verify): nothing here
boots a guest, takes a lock, or needs privilege.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLI = ROOT / "scripts" / "kcrypto-qemu-demo.py"


def fixture_manifest() -> dict:
    return {
        "$schema": "kcrypto.qemu-demo.inputs/v1",
        "campaign": "kcrypto-demo-qemu",
        "manifest_version": 1,
        "frozen_utc": "2026-09-30T00:00:00Z",
        "freeze_rule": "fixture",
        "product": {
            "repo_sha": "ab" * 20,
            "cli_sha": "cd" * 32,
            "bpf_agg_sha": "ef" * 32,
            "bpf_lc_sha": "12" * 32,
        },
        "qemu": {
            "path": "/usr/bin/qemu-system-x86_64",
            "version": "10.2.1",
            "sha256": "34" * 32,
        },
        "images": [
            {
                "id": "img-7014-base",
                "kernel": "7.0.14",
                "vmlinuz": "/frozen/vmlinuz",
                "vmlinuz_sha256": "56" * 32,
                "config_sha256": "78" * 32,
                "initramfs": "/frozen/initramfs",
                "initramfs_sha256": "9a" * 32,
                "rootfs": "/frozen/root",
                "rootfs_sha256": "bc" * 32,
                "rootfs_format": "qcow2",
                "cpu": {"model": "host", "flags": []},
                "devices": [],
            }
        ],
        "cells": [
            {
                "id": "D06",
                "title": "fixture",
                "image": "img-7014-base",
                "workload": {"kind": "nested-fallback"},
                "limits": {"timeout_s": 180},
                "expected_evidence": ["cell-D06.json"],
            }
        ],
    }


def run_cli(*argv: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *argv],
        capture_output=True, text=True, timeout=60, cwd=str(cwd),
    )


class CliTests(unittest.TestCase):
    def test_plan_lists_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "INPUTS.json"
            manifest.write_text(json.dumps(fixture_manifest()))
            proc = run_cli("plan", "--manifest", str(manifest))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("D06", proc.stdout)

    def test_run_unknown_cell_is_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "INPUTS.json"
            manifest.write_text(json.dumps(fixture_manifest()))
            proc = run_cli("run", "--manifest", str(manifest),
                           "--cell", "FROB", "--run-dir",
                           str(Path(tmp) / "FROB"),
                           "--lock", str(Path(tmp) / "lock"))
        self.assertEqual(proc.returncode, 2)

    def test_run_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "INPUTS.json"
            manifest.write_text(json.dumps(fixture_manifest()))
            taken = Path(tmp) / "D06"
            taken.mkdir()
            proc = run_cli("run", "--manifest", str(manifest),
                           "--cell", "D06", "--run-dir", str(taken),
                           "--lock", str(Path(tmp) / "lock"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("refusing to reuse", proc.stderr)

    def test_run_d06_seals_unsupported_without_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "INPUTS.json"
            manifest.write_text(json.dumps(fixture_manifest()))
            cell_dir = root / "D06"
            proc = run_cli("run", "--manifest", str(manifest),
                           "--cell", "D06", "--run-dir", str(cell_dir),
                           "--lock", str(root / "lock"))
            self.assertEqual(proc.returncode, 3, proc.stderr + proc.stdout)
            receipt = json.loads(
                (cell_dir / "cell-D06.json").read_text())
            self.assertEqual(receipt["verdict"], "UNSUPPORTED")
            self.assertTrue(receipt["reason"])
            self.assertTrue(receipt["positive_control"])
            self.assertTrue((cell_dir / "SHA256SUMS").is_file())
            # No guest ever booted: no spawn, no console, no overlay.
            self.assertFalse((cell_dir / "spawn.json").exists())
            self.assertFalse((cell_dir / "console.log").exists())

    def test_verify_offline_judges_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "INPUTS.json"
            manifest.write_text(json.dumps(fixture_manifest()))
            cell_dir = root / "D06"
            run_cli("run", "--manifest", str(manifest),
                    "--cell", "D06", "--run-dir", str(cell_dir),
                    "--lock", str(root / "lock"))
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("UNSUPPORTED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
