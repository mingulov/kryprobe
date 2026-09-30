#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned disk-backed QEMU guests for the P10 demo campaign (Task 1).

One guest at a time under the task lane lock plus the reconciled
common kvm-host flock. Every guest records
its exact identity — PID plus start ticks (never a PID alone),
QMP socket, overlay and backing identities — in ``spawn.json``
BEFORE any control command. QEMU is driven with ``subprocess.Popen``,
monotonic deadlines, explicit wait/reap and Unix QMP messages.
Never a wildcard PID kill, never a shared overlay, never a guessed
stale socket. A timeout stops and reaps the owned process group and
reports ``timed_out`` — the reconciler fails such a receipt, so a
timed-out worker can never yield PASS. Cleanup signals only the
owned live identity: a changed start-tick reading refuses to signal
(possible PID reuse) instead of killing a stranger.
"""

from __future__ import annotations

import fcntl
import json
import os
import pathlib
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field

from kcrypto_qemu_demo.receipts import (
    KNOWN_CELLS,
    SCHEMA_CELL,
    atomic_write_json,
    verify_artifact,
)


class GuestError(RuntimeError):
    """Owned-guest custody failure (locks, identity, QMP, stop, cleanup)."""


# Cells the guest dispatcher understands (campaign cells + PROBE).
GUEST_CELLS = frozenset(KNOWN_CELLS | {"PROBE"})


@dataclass
class OwnedGuest:
    """An owned QEMU lane: exact identities, held locks, live handle."""

    name: str
    run_dir: pathlib.Path
    proc: subprocess.Popen
    qemu_pid: int
    qemu_start_ticks: str
    qmp_socket: str
    overlay: str
    backing: str
    preexisting_qemu: dict
    cmd: list = field(default_factory=list)
    lock_files: list = field(default_factory=list)
    lock_paths: list = field(default_factory=list)


def acquire_locks(paths: list[pathlib.Path]) -> list:
    """Open and nonblocking-exclusive-flock every lock path.

    Raises :class:`GuestError` if any lock is held (never blocks —
    a contended lane is busy, not slow).
    """
    held = []
    try:
        for path in paths:
            path = pathlib.Path(path)
            fh = path.open("a+")
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as err:
                fh.close()
                raise GuestError(f"lock {path} is held by another lane: {err}") from err
            held.append(fh)
    except BaseException:
        for fh in held:
            fh.close()
        raise
    return held


def qemu_inventory() -> dict:
    """PID -> {args, start_ticks} for live qemu-system processes."""
    found: dict[str, dict] = {}
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            args = (proc / "cmdline").read_bytes().split(b"\0")
            if not args or not args[0]:
                continue
            decoded = [a.decode(errors="replace") for a in args if a]
            if pathlib.Path(decoded[0]).name.startswith("qemu-system"):
                start_ticks = (proc / "stat").read_text().split(") ", 1)[1].split()[19]
                found[proc.name] = {"args": decoded, "start_ticks": start_ticks}
        except (OSError, IndexError):
            pass
    return found


def _start_ticks(pid: int) -> str:
    """Start-tick identity of a live PID (raises if the PID is gone)."""
    try:
        return (
            pathlib.Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[19]
        )
    except (OSError, IndexError) as err:
        raise GuestError(f"cannot read start ticks of pid {pid}: {err}") from err


def owned_identity_ok(pid: int, expected_ticks: str) -> bool:
    """True iff PID is live with exactly the expected start ticks."""
    try:
        return _start_ticks(pid) == expected_ticks
    except GuestError:
        return False


def _preexisting_unchanged(before: dict, after: dict) -> tuple[bool, list]:
    """Exact-identity comparison of preexisting qemu processes."""
    reused = []
    for pid, facts in before.items():
        now = after.get(pid)
        if now is None:
            return False, reused
        if now != facts:
            if now.get("start_ticks") != facts.get("start_ticks"):
                reused.append(pid)
            return False, reused
    return True, reused


def _qemu_cmd(
    qemu: dict,
    image: dict,
    *,
    overlay: pathlib.Path,
    data_disk: pathlib.Path | None,
    qmp_socket: pathlib.Path,
    console_log: pathlib.Path,
    cell_id: str | None = None,
) -> list[str]:
    """Build the frozen QEMU command line (no host-root sharing, no network).

    ``cell_id`` (when given) selects the guest workload through the
    kernel command line (``kcrypto.cell=<ID>``); unknown or blank
    IDs refuse — the guest must never boot an ambiguous cell.
    """
    append = "console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 panic=-1"
    if cell_id is not None:
        if not cell_id or any(ch.isspace() for ch in cell_id):
            raise GuestError(f"blank cell selector {cell_id!r} (refusing)")
        if cell_id not in GUEST_CELLS:
            raise GuestError(f"unknown cell selector {cell_id!r} (refusing)")
        append += f" kcrypto.cell={cell_id}"
    cmd = [
        qemu["path"],
        "-accel", "kvm",
        "-cpu", image["cpu"]["model"],
        "-machine", "q35",
        "-smp", "4",
        "-m", "4G",
        "-display", "none",
        "-serial", f"file:{console_log}",
        "-kernel", image["vmlinuz"],
        "-initrd", image["initramfs"],
        "-append", append,
        "-drive", f"file={overlay},format=qcow2,if=virtio",
        "-qmp", f"unix:{qmp_socket},server=on,wait=off",
        "-nic", "none",
        "-no-reboot",
    ]
    if data_disk is not None:
        cmd += ["-drive", f"file={data_disk},format=qcow2,if=virtio"]
    # q35's pcie.0 root bus refuses hotplug ("Bus 'pcie.0' does not
    # support hotplugging"), so the removal cell hangs its crypto
    # device off a hotplug-capable root port; other cells keep the
    # plain root-bus attachment.
    hotplug_port = cell_id == "D05" and bool(image["devices"])
    if hotplug_port:
        cmd += ["-device", "pcie-root-port,id=rp0,hotplug=on"]
    for index, device in enumerate(image["devices"]):
        backend = f"cryptodev-backend-builtin,id=crypto_backend{index}"
        cmd += ["-object", backend]
        spec = (f"virtio-crypto-pci,id={device},"
                f"cryptodev=crypto_backend{index}")
        if hotplug_port:
            spec += ",bus=rp0"
        cmd += ["-device", spec]
    return cmd


def launch_guest(
    *,
    manifest: dict,
    image_id: str,
    run_dir: pathlib.Path,
    name: str,
    lock_paths: list[pathlib.Path],
    qemu_cmd_override: list[str] | None = None,
    console_name: str = "console.log",
    needs_data_disk: bool = False,
    cell_id: str | None = None,
    refuse_foreign: bool = False,
) -> OwnedGuest:
    """Launch one owned disk-backed guest under the lane locks.

    ``run_dir`` must exist and must not already hold ``spawn.json``
    (fresh output per run). Staged artifacts are hash-verified
    against the frozen manifest BEFORE the spawn — a mismatch
    raises, releases the locks, and writes no receipt. The fresh
    overlay is created from the pinned backing file (never shared,
    never reused). ``qemu_cmd_override`` is host-test-only: harmless
    host binaries (``true``/``sleep``) stand in for QEMU so custody
    is unit-testable without KVM. ``refuse_foreign`` refuses the
    launch when foreign qemu processes exist instead of booting
    beside them (releases the locks, writes no receipt, never
    signals the foreign processes); otherwise the explicit
    preexisting set is recorded and the stop path fails closed on
    any change.
    """
    run_dir = pathlib.Path(run_dir)
    if not run_dir.is_dir():
        raise GuestError(f"run dir {run_dir} does not exist (create it fresh first)")
    spawn_receipt = run_dir / "spawn.json"
    if spawn_receipt.exists():
        raise GuestError(f"run dir {run_dir} already used (refusing reuse)")
    images = {image["id"]: image for image in manifest["images"]}
    if image_id not in images:
        raise GuestError(f"unknown image {image_id!r}")
    image = images[image_id]
    held = acquire_locks([pathlib.Path(p) for p in lock_paths])
    try:
        before = qemu_inventory()
        if refuse_foreign and before:
            raise GuestError(
                "refusing launch beside foreign qemu PIDs "
                f"{sorted(before)} (--refuse-foreign: wait for a "
                "clean lane instead)"
            )
        overlay = run_dir / "disk-overlay.qcow2"
        qmp_socket = run_dir / "qmp.sock"
        console_log = run_dir / console_name
        data_disk = run_dir / "data-disk.qcow2" if needs_data_disk else None
        if qemu_cmd_override is None:
            from kcrypto_qemu_demo.receipts import ArtifactError

            try:
                verify_artifact(pathlib.Path(manifest["qemu"]["path"]),
                                manifest["qemu"]["sha256"])
                verify_artifact(pathlib.Path(image["vmlinuz"]), image["vmlinuz_sha256"])
                verify_artifact(pathlib.Path(image["initramfs"]),
                                image["initramfs_sha256"])
                verify_artifact(pathlib.Path(image["rootfs"]), image["rootfs_sha256"])
            except ArtifactError as err:
                raise GuestError(f"frozen input refused: {err}") from err
            if qmp_socket.exists():
                raise GuestError(f"stale QMP socket {qmp_socket} (refusing reuse)")
            backing_fmt = image["rootfs_format"]
            make = subprocess.run(
                ["qemu-img", "create", "-f", "qcow2",
                 "-b", image["rootfs"], "-F", backing_fmt, str(overlay)],
                capture_output=True, text=True, timeout=120,
            )
            if make.returncode != 0 or not overlay.is_file():
                raise GuestError(f"overlay creation failed: {make.stderr[-500:]}")
            if data_disk is not None:
                fresh = subprocess.run(
                    ["qemu-img", "create", "-f", "qcow2", str(data_disk), "1G"],
                    capture_output=True, text=True, timeout=120,
                )
                if fresh.returncode != 0 or not data_disk.is_file():
                    raise GuestError(f"data-disk creation failed: {fresh.stderr[-500:]}")
            cmd = _qemu_cmd(
                manifest["qemu"], image, overlay=overlay, data_disk=data_disk,
                qmp_socket=qmp_socket, console_log=console_log,
                cell_id=cell_id,
            )
        else:
            cmd = list(qemu_cmd_override)
        proc = subprocess.Popen(cmd, start_new_session=True)
        start_ticks = _start_ticks(proc.pid)
        atomic_write_json(
            spawn_receipt,
            {
                "name": name,
                "image_id": image_id,
                "cell_id": cell_id,
                "qemu_pid": proc.pid,
                "qemu_start_ticks": start_ticks,
                "cmd": cmd,
                "qmp_socket": str(qmp_socket),
                "overlay": str(overlay),
                "backing": image["rootfs"],
                "data_disk": str(data_disk) if data_disk else None,
                "overlay_created": qemu_cmd_override is None,
                "lock_paths": [str(p) for p in lock_paths],
                "preexisting_qemu_pids": sorted(before),
                "refuse_foreign": bool(refuse_foreign),
                "manifest_sha256": manifest.get("_manifest_sha256"),
            },
        )
    except BaseException:
        for fh in held:
            fh.close()
        raise
    return OwnedGuest(
        name=name,
        run_dir=run_dir,
        proc=proc,
        qemu_pid=proc.pid,
        qemu_start_ticks=start_ticks,
        qmp_socket=str(qmp_socket),
        overlay=str(overlay),
        backing=image["rootfs"],
        preexisting_qemu=before,
        cmd=cmd,
        lock_files=held,
        lock_paths=[str(p) for p in lock_paths],
    )


def qmp_exchange(sock: socket.socket, command: dict, timeout_s: float = 10.0) -> dict:
    """One QMP transaction on a connected socket: greeting, handshake, command.

    Pure framing over an already-connected socket (unit-testable via
    socketpair). Raises :class:`GuestError` on greeting/protocol errors.
    """
    sock.settimeout(timeout_s)
    fh = sock.makefile("r")
    try:
        greeting = fh.readline()
    except (OSError, ValueError) as err:
        raise GuestError(f"QMP greeting unreadable: {err}") from err
    try:
        json.loads(greeting)
    except (json.JSONDecodeError, TypeError) as err:
        raise GuestError(f"QMP greeting is not JSON: {err}") from err
    for payload in ({"execute": "qmp_capabilities"}, dict(command)):
        try:
            sock.sendall((json.dumps(payload) + "\n").encode())
            reply = json.loads(fh.readline())
        except (OSError, ValueError, json.JSONDecodeError) as err:
            raise GuestError(f"QMP exchange failed for {payload!r}: {err}") from err
    return reply


def qmp_command(guest: OwnedGuest, command: dict, timeout_s: float = 10.0) -> dict:
    """Send one QMP command to the owned guest (owned socket only)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect(guest.qmp_socket)
        return qmp_exchange(sock, command, timeout_s=timeout_s)
    except OSError as err:
        raise GuestError(f"QMP connect to owned socket failed: {err}") from err
    finally:
        sock.close()


def qmp_device_del_and_wait(
    sock: socket.socket, device_id: str, timeout_s: float = 60.0
) -> dict:
    """Delete one owned device and wait for its exact removal event.

    Operates on an already-connected QMP socket (unit-testable via
    socketpair): greeting, handshake, ``device_del``, then reads
    until BOTH the command's ``{"return": {}}`` AND the matching
    ``DEVICE_DELETED`` event for ``device_id`` arrive (either
    order), bounded by a monotonic ``timeout_s`` deadline.
    Unrelated events are ignored but a missing event, a command
    error, or a closed socket refuses — removal is never assumed.
    Returns the matching event object.
    """
    if not device_id or any(ch.isspace() for ch in str(device_id)):
        raise GuestError(f"blank QMP device id {device_id!r} (refusing)")
    deadline = time.monotonic() + timeout_s
    sock.settimeout(timeout_s)
    fh = sock.makefile("r")
    try:
        greeting = fh.readline()
    except (OSError, ValueError) as err:
        raise GuestError(f"QMP greeting unreadable: {err}") from err
    try:
        json.loads(greeting)
    except (json.JSONDecodeError, TypeError) as err:
        raise GuestError(f"QMP greeting is not JSON: {err}") from err
    try:
        sock.sendall(b'{"execute": "qmp_capabilities"}\n')
        json.loads(fh.readline())
        sock.sendall(
            (json.dumps({"execute": "device_del",
                         "arguments": {"id": device_id}}) + "\n").encode()
        )
    except (OSError, ValueError) as err:
        raise GuestError(f"QMP device_del send failed: {err}") from err
    returned = False
    pending_event: dict | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GuestError(
                f"timed out waiting for DEVICE_DELETED {device_id!r}"
                f" (returned={returned})"
            )
        sock.settimeout(remaining)
        try:
            line = fh.readline()
        except (OSError, ValueError) as err:
            raise GuestError(
                f"QMP event read failed waiting for DEVICE_DELETED"
                f" {device_id!r}: {err}"
            ) from err
        if not line:
            raise GuestError(
                f"QMP closed waiting for DEVICE_DELETED {device_id!r}"
            )
        try:
            message = json.loads(line)
        except json.JSONDecodeError as err:
            raise GuestError(f"QMP event is not JSON: {err}") from err
        if not isinstance(message, dict):
            raise GuestError(f"QMP event is not an object: {message!r}")
        if "event" in message:
            if (
                message.get("event") == "DEVICE_DELETED"
                and isinstance(message.get("data"), dict)
                and message["data"].get("device") == device_id
            ):
                if returned:
                    return message
                # Event arrived first: keep reading for the return.
                pending_event = message
            continue
        if "error" in message:
            raise GuestError(f"QMP device_del {device_id!r} refused: {message}")
        if "return" in message:
            returned = True
            if isinstance(pending_event, dict):
                return pending_event
            continue
        raise GuestError(f"QMP unexpected message during device_del: {message!r}")


def qmp_remove_device(
    guest: OwnedGuest, device_id: str, timeout_s: float = 60.0
) -> dict:
    """Remove one device from the owned guest (owned socket only)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        try:
            sock.connect(guest.qmp_socket)
        except OSError as err:
            raise GuestError(
                f"QMP connect to owned socket failed: {err}"
            ) from err
        return qmp_device_del_and_wait(sock, device_id, timeout_s=timeout_s)
    finally:
        sock.close()


def wait_guest(guest: OwnedGuest, timeout_s: float, poll_s: float = 1.0) -> dict:
    """Wait (bounded, monotonic) for the guest command; stop it on timeout.

    Returns ``{"exit": int|None, "timed_out": bool}``. A timeout
    stops and reaps the owned process group — a timed-out worker can
    never yield PASS (callers must treat ``timed_out`` as failure).
    """
    start = time.monotonic()
    while guest.proc.poll() is None:
        if time.monotonic() - start > timeout_s:
            return {"exit": _kill_group(guest), "timed_out": True}
        time.sleep(poll_s)
    return {"exit": guest.proc.wait(), "timed_out": False}


def _kill_group(guest: OwnedGuest, grace_s: float = 10.0) -> int | None:
    """SIGTERM then SIGKILL the owned process group; return exit code.

    Refuses to signal unless the owned PID is live with exactly the
    recorded start ticks (a changed reading is possible PID reuse —
    never kill a stranger).
    """
    if not owned_identity_ok(guest.proc.pid, guest.qemu_start_ticks):
        raise GuestError(
            f"owned pid {guest.proc.pid} identity changed "
            f"(expected ticks {guest.qemu_start_ticks} — refusing to signal)"
        )
    try:
        os.killpg(guest.proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        return guest.proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        pass
    if not owned_identity_ok(guest.proc.pid, guest.qemu_start_ticks):
        raise GuestError(
            f"owned pid {guest.proc.pid} identity changed during stop "
            f"(refusing to signal)"
        )
    try:
        os.killpg(guest.proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        return guest.proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired as err:
        raise GuestError(
            f"owned guest pid {guest.proc.pid} survived SIGKILL "
            f"(leaked owned resource — investigate, do not pass)"
        ) from err


def stop_guest(guest: OwnedGuest) -> dict:
    """Stop (if running), reap, verify cleanup, release locks.

    An already-exited guest is never signaled. A live guest is
    signaled only through its verified owned identity. Verifies no
    remaining owned qemu and every preexisting qemu PID still
    present with identical args + start ticks (a reused PID refuses
    the comparison). Writes ``stop.json``, releases locks last.
    """
    proc = guest.proc
    if proc.poll() is None:
        exit_code = _kill_group(guest)
        stopped = True
    else:
        exit_code = proc.wait()
        stopped = False
    reaped = proc.returncode is not None
    after = qemu_inventory()
    remaining = {
        pid: facts
        for pid, facts in after.items()
        if guest.name in " ".join(facts["args"])
    }
    unchanged, reused = _preexisting_unchanged(guest.preexisting_qemu, after)
    fragment = {
        "qemu_pid": guest.qemu_pid,
        "vng_exit": exit_code,
        "stopped_by_helper": stopped,
        "reaped": reaped,
        "remaining_owned_qemu": remaining,
        "preexisting_qemu_unchanged": unchanged,
        "preexisting_pid_reused": reused,
    }
    atomic_write_json(guest.run_dir / "stop.json", fragment)
    for fh in guest.lock_files:
        fh.close()
    guest.lock_files.clear()
    return fragment


def _wait_for_console_mark(
    guest: OwnedGuest,
    console_log: pathlib.Path,
    needle: str,
    timeout_s: float,
    poll_s: float = 1.0,
) -> bool:
    """Poll the serial log for a guest mark (bounded, monotonic).

    Returns True on the first sighting, False when the guest exits
    first or the budget expires — the caller judges a missed mark
    as failed evidence, never as success.
    """
    start = time.monotonic()
    while True:
        try:
            text = console_log.read_text(errors="replace")
        except OSError:
            text = ""
        if needle in text:
            return True
        if guest.proc.poll() is not None:
            return False
        if time.monotonic() - start > timeout_s:
            return False
        time.sleep(poll_s)


def run_cell(
    *,
    guest: OwnedGuest,
    cell: dict,
    run_dir: pathlib.Path,
    run_id: str,
    manifest_sha256: str | None,
    qmp_device: str | None = None,
) -> pathlib.Path:
    """Run one manifest cell against the owned guest (bounded wait).

    The harness cell keeps its legacy console check; every D-cell
    parses the full console into sealed ledgers through
    :mod:`cells` (exact counts, gapless sequences, ordered marks).
    The removal cell additionally drives one QMP ``device_del``
    mid-flight once the guest marks QUIESCED, and records the
    exact removal event (or its absence) for the receipt. The
    caller stops the guest afterwards and finalizes the receipt
    with the stop fragment. Returns the receipt path.
    """
    from kcrypto_qemu_demo import cells as cell_builders

    run_dir = pathlib.Path(run_dir)
    timeout_s = cell["limits"]["timeout_s"]
    kind = cell["workload"].get("kind")
    console_log = run_dir / "console.log"
    if kind == "cold-boot-no-observer":
        wait = wait_guest(guest, timeout_s)
        try:
            text = console_log.read_text(errors="replace")
        except OSError:
            text = ""
        receipt = {
            "$schema": SCHEMA_CELL,
            "run_id": run_id,
            "cell_id": cell["id"],
            "image": guest.name,
            "verdict": "RUN",
            "process": {
                "exit": wait["exit"],
                "timed_out": wait["timed_out"],
                "reaped": guest.proc.returncode is not None,
            },
            "observation": {"expected": 1,
                            "actual": 1 if "INIT-READY" in text else 0},
            "checks": {"console_has_init_ready": "INIT-READY" in text},
            "custody": {"manifest_sha256": manifest_sha256},
        }
        receipt_path = run_dir / f"cell-{cell['id']}.json"
        atomic_write_json(receipt_path, receipt)
        return receipt_path
    extra: dict = {}
    deadline = time.monotonic() + timeout_s
    if kind == "device-removal":
        if not qmp_device:
            raise GuestError("device-removal needs exactly one QMP device")
        quiesce_budget = max(1.0, timeout_s - 70.0)
        seen = _wait_for_console_mark(
            guest, console_log, '"name": "QUIESCED"', quiesce_budget)
        if not seen:
            extra = {"expected_device": qmp_device, "qmp_events": [],
                     "qmp_error": "guest never marked QUIESCED"}
        else:
            try:
                event = qmp_remove_device(guest, qmp_device,
                                          timeout_s=min(
                                              60.0, deadline -
                                              time.monotonic()))
                extra = {"expected_device": qmp_device,
                         "qmp_events": [event], "qmp_error": None}
            except GuestError as err:
                extra = {"expected_device": qmp_device, "qmp_events": [],
                         "qmp_error": str(err)}
    remaining = max(1.0, deadline - time.monotonic())
    wait = wait_guest(guest, remaining)
    try:
        text = console_log.read_text(errors="replace")
    except OSError:
        text = ""
    receipt, ledgers = cell_builders.build_cell(
        cell, run_id, manifest_sha256, text,
        {"exit": wait["exit"], "timed_out": wait["timed_out"],
         "reaped": guest.proc.returncode is not None},
        guest.name, extra=extra or None,
    )
    for name, body in sorted(ledgers.items()):
        (run_dir / name).write_text(body)
    receipt_path = run_dir / f"cell-{cell['id']}.json"
    atomic_write_json(receipt_path, receipt)
    return receipt_path
