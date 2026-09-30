#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the demo CLI surface (attempt 4).

The CLI script is not importable (hyphenated name), so these tests
drive it through subprocess with a fixture manifest. Only offline
paths are exercised (plan, unknown-cell refusal, reuse refusal,
the no-boot D06 UNSUPPORTED lane, offline verify): nothing here
boots a guest, takes a lock, or needs privilege.
"""

import hashlib
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
            # The no-boot seal still pins its manifest (no process
            # key: no worker process ever existed).
            want = hashlib.sha256(
                manifest.read_bytes()).hexdigest()
            self.assertEqual(receipt["custody"],
                             {"manifest_sha256": want})
            self.assertNotIn("process", receipt)
            self.assertTrue((cell_dir / "SHA256SUMS").is_file())
            # No guest ever booted: no spawn, no console, no overlay.
            self.assertFalse((cell_dir / "spawn.json").exists())
            self.assertFalse((cell_dir / "console.log").exists())

    def test_run_accepts_refuse_foreign(self):
        # R7 RED: the no-boot lane accepts (and ignores) the flag.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "INPUTS.json"
            manifest.write_text(json.dumps(fixture_manifest()))
            cell_dir = root / "D06"
            proc = run_cli("run", "--manifest", str(manifest),
                           "--cell", "D06", "--run-dir", str(cell_dir),
                           "--lock", str(root / "lock"),
                           "--refuse-foreign")
            self.assertEqual(proc.returncode, 3, proc.stderr + proc.stdout)

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

    def _sealed_pass_dir(self, root: Path) -> Path:
        # Hand-sealed PASS dir: run.json + one all-true RUN receipt
        # + SHA256SUMS (hashlib only, no harness import).
        cell_dir = root / "D09"
        cell_dir.mkdir()
        (cell_dir / "run.json").write_text(json.dumps(
            {"run_id": "run9", "cell_id": "D09"}))
        (cell_dir / "cell-D09.json").write_text(json.dumps(
            {"$schema": "kcrypto.qemu-demo.cell/v1",
             "run_id": "run9", "cell_id": "D09", "verdict": "RUN",
             "process": {"exit": 0, "timed_out": False,
                         "reaped": True},
             "cleanup": {"remaining_owned": {},
                         "preexisting_unchanged": True},
             "custody": {"manifest_sha256": "ab" * 32},
             "observation": {"expected": 1, "actual": 1},
             "checks": {"console_has_init_ready": True}}))
        lines = ""
        for name in ("cell-D09.json", "run.json"):
            digest = hashlib.sha256(
                (cell_dir / name).read_bytes()).hexdigest()
            lines += f"{digest}  {name}\n"
        (cell_dir / "SHA256SUMS").write_text(lines)
        return cell_dir

    def test_verify_passes_intact_sealed_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cell_dir = self._sealed_pass_dir(Path(tmp))
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("campaign: PASS", proc.stdout)

    def test_verify_rejects_tampered_seal(self):
        # R8 RED: verify must check SHA256SUMS contents, not just
        # its existence.
        with tempfile.TemporaryDirectory() as tmp:
            cell_dir = self._sealed_pass_dir(Path(tmp))
            with (cell_dir / "run.json").open("a") as fh:
                fh.write(" ")
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("seal", proc.stdout)
        self.assertIn("campaign: FAIL", proc.stdout)

    def test_verify_rejects_missing_sealed_file(self):
        # R8 RED: a sealed entry deleted after sealing must fail.
        with tempfile.TemporaryDirectory() as tmp:
            cell_dir = self._sealed_pass_dir(Path(tmp))
            (cell_dir / "run.json").unlink()
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("seal", proc.stdout)
        self.assertIn("campaign: FAIL", proc.stdout)

    def test_verify_rejects_empty_seal(self):
        # R2-1 RED: a vacuous seal must fail, never PASS.
        with tempfile.TemporaryDirectory() as tmp:
            cell_dir = self._sealed_pass_dir(Path(tmp))
            (cell_dir / "SHA256SUMS").write_text("")
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("empty", proc.stdout)
        self.assertIn("campaign: FAIL", proc.stdout)

    def test_verify_rejects_whitespace_seal(self):
        # R2-1 RED: a whitespace-only seal is vacuous too.
        with tempfile.TemporaryDirectory() as tmp:
            cell_dir = self._sealed_pass_dir(Path(tmp))
            (cell_dir / "SHA256SUMS").write_text("  \n\t\n")
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("empty", proc.stdout)
        self.assertIn("campaign: FAIL", proc.stdout)

    def test_verify_rejects_omitted_receipt(self):
        # R2-1 RED (D07-late shape): the judged receipt dropped
        # from the seal while its checks read PASS must fail
        # closed with an explicit unsealed-receipt reason.
        with tempfile.TemporaryDirectory() as tmp:
            cell_dir = self._sealed_pass_dir(Path(tmp))
            lines = (cell_dir / "SHA256SUMS").read_text().splitlines()
            kept = [ln for ln in lines if "cell-D09.json" not in ln]
            self.assertTrue(kept)  # run.json entry still seals
            (cell_dir / "SHA256SUMS").write_text("\n".join(kept) + "\n")
            proc = run_cli("verify", "--run-dir", str(cell_dir))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("cell-D09.json", proc.stdout)
        self.assertIn("campaign: FAIL", proc.stdout)


if __name__ == "__main__":
    unittest.main()
