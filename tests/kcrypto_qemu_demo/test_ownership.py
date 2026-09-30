#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for demo QEMU custody: locks, identity, QMP framing (Task 1).

Standard library only; no privilege, no real qemu. Guest commands
under test are harmless host binaries (``true``/``sleep``) via the
host-test-only command override; QMP framing is tested against a
fake QMP server on a socketpair. Control is never authorized
through a PID alone: a reused PID refuses the comparison and is
never signaled.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import runner  # noqa: E402


def live_pids():
    return {p.name for p in Path("/proc").iterdir() if p.name.isdigit()}


def test_manifest():
    return {
        "$schema": "kcrypto.qemu-demo.inputs/v1",
        "campaign": "kcrypto-demo-qemu",
        "manifest_version": 1,
        "product": {"repo_sha": "00" * 20},
        "qemu": {"path": "/usr/bin/qemu-system-x86_64", "version": "10.2.1", "sha256": "00" * 32},
        "images": [
            {
                "id": "img-test",
                "kernel": "7.0.14",
                "vmlinuz": "/frozen/vmlinuz",
                "vmlinuz_sha256": "11" * 32,
                "config_sha256": "22" * 32,
                "initramfs": "/frozen/initramfs.cpio",
                "initramfs_sha256": "33" * 32,
                "rootfs": "/frozen/root.raw",
                "rootfs_sha256": "44" * 32,
                "rootfs_format": "raw",
                "cpu": {"model": "host", "flags": []},
                "devices": [],
            }
        ],
        "cells": [],
    }


class OwnershipTests(unittest.TestCase):
    def test_true_command_passes_with_spawn_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            guest = runner.launch_guest(
                manifest=test_manifest(),
                image_id="img-test",
                run_dir=run_dir,
                name="demo-test-guest",
                lock_paths=[lock],
                qemu_cmd_override=["true"],
            )
            try:
                self.assertEqual(guest.qemu_pid, guest.proc.pid)
                self.assertTrue(guest.qemu_start_ticks.isdigit())
                # PID + start ticks + QMP + overlay identity before control.
                spawn = json.loads((run_dir / "spawn.json").read_text())
                self.assertEqual(spawn["qemu_pid"], guest.proc.pid)
                self.assertEqual(spawn["qemu_start_ticks"], guest.qemu_start_ticks)
                self.assertTrue(spawn["qmp_socket"].endswith("qmp.sock"))
                self.assertTrue(spawn["overlay"].endswith("disk-overlay.qcow2"))
                self.assertEqual(spawn["backing"], "/frozen/root.raw")
                wait = runner.wait_guest(guest, timeout_s=30)
                self.assertEqual(wait, {"exit": 0, "timed_out": False})
            finally:
                stop = runner.stop_guest(guest)
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
            first = runner.launch_guest(
                manifest=test_manifest(),
                image_id="img-test",
                run_dir=run_dir,
                name="demo-test-guest",
                lock_paths=[lock],
                qemu_cmd_override=["true"],
            )
            runner.wait_guest(first, timeout_s=30)
            runner.stop_guest(first)
            with self.assertRaisesRegex(runner.GuestError, "already used"):
                runner.launch_guest(
                    manifest=test_manifest(),
                    image_id="img-test",
                    run_dir=run_dir,
                    name="demo-test-guest",
                    lock_paths=[lock],
                    qemu_cmd_override=["true"],
                )

    def test_missing_run_dir_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(runner.GuestError, "does not exist"):
                runner.launch_guest(
                    manifest=test_manifest(),
                    image_id="img-test",
                    run_dir=Path(tmp) / "absent",
                    name="demo-test-guest",
                    lock_paths=[Path(tmp) / "lane.lock"],
                    qemu_cmd_override=["true"],
                )

    def test_contended_lock_refuses_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            held = runner.acquire_locks([lock])
            try:
                start = time.monotonic()
                with self.assertRaisesRegex(runner.GuestError, "held by another"):
                    runner.launch_guest(
                        manifest=test_manifest(),
                        image_id="img-test",
                        run_dir=run_dir,
                        name="demo-test-guest",
                        lock_paths=[lock],
                        qemu_cmd_override=["true"],
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
            guest = runner.launch_guest(
                manifest=test_manifest(),
                image_id="img-test",
                run_dir=run_dir,
                name="demo-test-guest",
                lock_paths=[lock],
                qemu_cmd_override=["sleep", "120"],
            )
            try:
                wait = runner.wait_guest(guest, timeout_s=1, poll_s=0.1)
                self.assertTrue(wait["timed_out"])
                self.assertIsNotNone(guest.proc.returncode)
            finally:
                stop = runner.stop_guest(guest)
            self.assertTrue(stop["reaped"])
            self.assertNotIn(str(guest.qemu_pid), live_pids() - before)

    def test_cleanup_rejects_reused_pid(self):
        # A reused preexisting PID refuses the comparison (never a pass).
        before = {"4242": {"args": ["qemu-system-x86_64", "old"], "start_ticks": "100"}}
        after = {"4242": {"args": ["qemu-system-x86_64", "new"], "start_ticks": "999"}}
        unchanged, reused = runner._preexisting_unchanged(before, after)
        self.assertFalse(unchanged)
        self.assertEqual(reused, ["4242"])

    def test_owned_identity_gate(self):
        pid = os.getpid()
        ticks = runner._start_ticks(pid)
        self.assertTrue(runner.owned_identity_ok(pid, ticks))
        self.assertFalse(runner.owned_identity_ok(pid, "0" if ticks != "0" else "1"))
        self.assertFalse(runner.owned_identity_ok(2**30, "100"))

    def test_stop_never_signals_reused_identity(self):
        # If the owned PID's start ticks changed, stop refuses to signal
        # (possible PID reuse) instead of killing a stranger.
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cell"
            run_dir.mkdir()
            lock = Path(tmp) / "lane.lock"
            guest = runner.launch_guest(
                manifest=test_manifest(),
                image_id="img-test",
                run_dir=run_dir,
                name="demo-test-guest",
                lock_paths=[lock],
                qemu_cmd_override=["sleep", "120"],
            )
            real_ticks = guest.qemu_start_ticks
            try:
                guest.qemu_start_ticks = "0" if real_ticks != "0" else "1"
                with self.assertRaisesRegex(runner.GuestError, "refusing to signal"):
                    runner.stop_guest(guest)
                # The stranger is untouched; restore identity and reap ours.
                self.assertIsNone(guest.proc.poll())
            finally:
                guest.qemu_start_ticks = real_ticks
                stop = runner.stop_guest(guest)
            self.assertTrue(stop["reaped"])

    def test_vanished_preexisting_qemu_fails_closed(self):
        before = {"4242": {"args": ["qemu-system-x86_64"], "start_ticks": "100"}}
        unchanged, _reused = runner._preexisting_unchanged(before, {})
        self.assertFalse(unchanged)

    def test_unchanged_preexisting_qemu_passes(self):
        facts = {"4242": {"args": ["qemu-system-x86_64"], "start_ticks": "100"}}
        unchanged, reused = runner._preexisting_unchanged(dict(facts), dict(facts))
        self.assertTrue(unchanged)
        self.assertEqual(reused, [])


class QemuCmdTests(unittest.TestCase):
    def test_qemu_cmd_routes_console_to_serial(self):
        # Without console=ttyS0 the guest's /dev/console writes go to
        # VGA, never to the captured serial log — the harness would
        # never observe INIT-READY.
        image = test_manifest()["images"][0]
        cmd = runner._qemu_cmd(
            test_manifest()["qemu"],
            image,
            overlay=Path("/run/disk-overlay.qcow2"),
            data_disk=None,
            qmp_socket=Path("/run/qmp.sock"),
            console_log=Path("/run/console.log"),
        )
        self.assertIn("-append", cmd)
        append = cmd[cmd.index("-append") + 1]
        self.assertIn("console=ttyS0", append)

    def test_qemu_cmd_has_no_host_sharing_or_network(self):
        image = test_manifest()["images"][0]
        cmd = runner._qemu_cmd(
            test_manifest()["qemu"],
            image,
            overlay=Path("/run/disk-overlay.qcow2"),
            data_disk=None,
            qmp_socket=Path("/run/qmp.sock"),
            console_log=Path("/run/console.log"),
        )
        joined = " ".join(cmd)
        for banned in ("9p", "virtiofs", "hostshare", "hostfwd"):
            self.assertNotIn(banned, joined)
        self.assertIn("-nic", cmd)
        self.assertEqual(cmd[cmd.index("-nic") + 1], "none")


class QmpTests(unittest.TestCase):
    def test_qmp_frames_handshake_and_command(self):
        # Fake QMP server: greeting, capabilities ack, echo the command.
        server, client = socket.socketpair()
        observed: list = []

        def serve():
            with server:
                server.sendall(b'{"QMP": {"version": {"qemu": {"micro": 1}}}}\n')
                fh = server.makefile("r")
                for line in fh:
                    observed.append(json.loads(line))
                    server.sendall(b'{"return": {}}\n')
                    if len(observed) == 2:
                        return

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with client:
                reply = runner.qmp_exchange(client, {"execute": "query-status"})
        finally:
            thread.join(timeout=10)
        self.assertEqual(reply, {"return": {}})
        self.assertEqual(observed[0], {"execute": "qmp_capabilities"})
        self.assertEqual(observed[1], {"execute": "query-status"})

    def test_qmp_greeting_error_refuses(self):
        server, client = socket.socketpair()

        def serve():
            with server:
                server.sendall(b'not-json\n')

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with client, self.assertRaisesRegex(runner.GuestError, "QMP greeting"):
                runner.qmp_exchange(client, {"execute": "query-status"})
        finally:
            thread.join(timeout=10)


if __name__ == "__main__":
    unittest.main()
