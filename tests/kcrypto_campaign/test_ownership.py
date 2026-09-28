#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for P8/T13 owned-guest custody + identity validation.

Standard library only; no guests, no privilege, no qemu. Guest
commands under test are harmless host binaries (``true``/``sleep``).
Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_ownership.py'
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_campaign import identity, owned_guest  # noqa: E402


def live_pids():
    return {p.name for p in Path("/proc").iterdir() if p.name.isdigit()}


class OwnershipTests(unittest.TestCase):
    def test_true_command_passes_with_spawn_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            guest = owned_guest.start_guest(
                vng_cmd=["true"],
                run_dir=run_dir,
                name="t13-test-guest",
                lock_paths=[lock],
            )
            try:
                self.assertEqual(guest.vng_pid, guest.proc.pid)
                self.assertTrue(guest.vng_start_ticks.isdigit())
                self.assertEqual(guest.cmd, ["true"])
                spawn = json.loads((run_dir / "spawn.json").read_text())
                self.assertEqual(spawn["vng_pid"], guest.proc.pid)
                self.assertEqual(spawn["cmd"], ["true"])
                wait = owned_guest.wait_guest(guest, timeout_s=30)
                self.assertEqual(wait, {"exit": 0, "timed_out": False})
            finally:
                stop = owned_guest.stop_guest(guest)
            self.assertTrue(stop["reaped"])
            self.assertEqual(stop["remaining_owned_qemu"], {})
            self.assertTrue(stop["preexisting_qemu_unchanged"])
            self.assertEqual(stop["preexisting_pid_reused"], [])
            self.assertTrue((run_dir / "stop.json").is_file())

    def test_run_dir_reuse_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            first = owned_guest.start_guest(
                vng_cmd=["true"],
                run_dir=run_dir,
                name="t13-test-guest",
                lock_paths=[lock],
            )
            owned_guest.wait_guest(first, timeout_s=30)
            owned_guest.stop_guest(first)
            with self.assertRaisesRegex(owned_guest.GuestError, "already used"):
                owned_guest.start_guest(
                    vng_cmd=["true"],
                    run_dir=run_dir,
                    name="t13-test-guest",
                    lock_paths=[lock],
                )

    def test_missing_run_dir_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(owned_guest.GuestError, "does not exist"):
                owned_guest.start_guest(
                    vng_cmd=["true"],
                    run_dir=Path(tmp) / "absent",
                    name="t13-test-guest",
                    lock_paths=[Path(tmp) / "lane.lock"],
                )

    def test_contended_lock_refuses_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            held = owned_guest.acquire_locks([lock])
            try:
                start = time.monotonic()
                with self.assertRaisesRegex(owned_guest.GuestError, "held by another"):
                    owned_guest.start_guest(
                        vng_cmd=["true"],
                        run_dir=run_dir,
                        name="t13-test-guest",
                        lock_paths=[lock],
                    )
                self.assertLess(time.monotonic() - start, 10)
            finally:
                for fh in held:
                    fh.close()

    def test_timeout_kills_and_reaps_without_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            before = live_pids()
            guest = owned_guest.start_guest(
                vng_cmd=["sleep", "120"],
                run_dir=run_dir,
                name="t13-test-guest",
                lock_paths=[lock],
            )
            try:
                wait = owned_guest.wait_guest(guest, timeout_s=1, poll_s=0.1)
                self.assertTrue(wait["timed_out"])
                # A timeout is a failure signal, never a pass input.
                self.assertIsNotNone(guest.proc.returncode)
            finally:
                stop = owned_guest.stop_guest(guest)
            self.assertTrue(stop["reaped"])
            self.assertNotIn(str(guest.vng_pid), live_pids() - before)

    def test_run_cell_wraps_start_wait_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            result = owned_guest.run_cell(
                portion_id="R01-det-7014",
                vng_cmd=["true"],
                run_dir=run_dir,
                name="t13-test-guest",
                lock_paths=[lock],
                timeout_s=30,
            )
            self.assertEqual(result["wait"], {"exit": 0, "timed_out": False})
            self.assertTrue(result["stop"]["reaped"])
            self.assertTrue((run_dir / "spawn.json").is_file())
            self.assertTrue((run_dir / "stop.json").is_file())

    def test_run_cell_timeout_stops_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            result = owned_guest.run_cell(
                portion_id="R01-det-7014",
                vng_cmd=["sleep", "120"],
                run_dir=run_dir,
                name="t13-test-guest",
                lock_paths=[lock],
                timeout_s=1,
            )
            self.assertTrue(result["wait"]["timed_out"])
            self.assertTrue(result["stop"]["reaped"])
            self.assertTrue((run_dir / "stop.json").is_file())

    def test_reused_preexisting_pid_refuses_comparison(self):
        before = {"4242": {"args": ["qemu-system-x86_64", "old"], "start_ticks": "100"}}
        after = {"4242": {"args": ["qemu-system-x86_64", "new"], "start_ticks": "999"}}
        unchanged, reused = owned_guest._preexisting_unchanged(before, after)
        self.assertFalse(unchanged)
        self.assertEqual(reused, ["4242"])

    def test_vanished_preexisting_qemu_fails_closed(self):
        before = {"4242": {"args": ["qemu-system-x86_64"], "start_ticks": "100"}}
        unchanged, _reused = owned_guest._preexisting_unchanged(before, {})
        self.assertFalse(unchanged)

    def test_unchanged_preexisting_qemu_passes(self):
        facts = {"4242": {"args": ["qemu-system-x86_64"], "start_ticks": "100"}}
        unchanged, reused = owned_guest._preexisting_unchanged(dict(facts), dict(facts))
        self.assertTrue(unchanged)
        self.assertEqual(reused, [])


class IdentityTests(unittest.TestCase):
    BEFORE = (
        "kernel=7.2.6-070206-generic\n"
        "config_sha=aaa\n"
        "btf_sha=bbb\n"
        "module_sha=ccc\n"
        "cli_sha=ddd\n"
        "bpf_agg_sha=eee\n"
        "bpf_lc_sha=fff\n"
        "oracle_sha=999\n"
    )

    def test_stable_identity_validates(self):
        before = identity.parse_identity_env(self.BEFORE)
        after = identity.parse_identity_env(self.BEFORE)
        verdict = identity.compare_identities(before, after)
        self.assertTrue(verdict["stable"])
        self.assertEqual(verdict["mismatches"], [])
        self.assertEqual(verdict["missing"], [])

    def test_changed_hash_fails(self):
        before = identity.parse_identity_env(self.BEFORE)
        after = identity.parse_identity_env(self.BEFORE.replace("cli_sha=ddd", "cli_sha=xyz"))
        verdict = identity.compare_identities(before, after)
        self.assertFalse(verdict["stable"])
        self.assertIn("cli_sha", verdict["mismatches"])

    def test_missing_key_fails(self):
        before = identity.parse_identity_env(self.BEFORE)
        after = dict(before)
        del after["btf_sha"]
        verdict = identity.compare_identities(before, after)
        self.assertFalse(verdict["stable"])
        self.assertIn("btf_sha", verdict["missing"])

    def test_empty_value_fails(self):
        with self.assertRaisesRegex(identity.IdentityError, "empty value"):
            identity.parse_identity_env("kernel=\n")

    def test_malformed_line_fails(self):
        with self.assertRaisesRegex(identity.IdentityError, "malformed"):
            identity.parse_identity_env("kernel 7.2.6\n")

    def test_kernel_change_fails(self):
        before = identity.parse_identity_env(self.BEFORE)
        after = identity.parse_identity_env(
            self.BEFORE.replace("kernel=7.2.6-070206-generic", "kernel=7.0.14-070014-generic")
        )
        verdict = identity.compare_identities(before, after)
        self.assertFalse(verdict["stable"])
        self.assertIn("kernel", verdict["mismatches"])


if __name__ == "__main__":
    unittest.main()
