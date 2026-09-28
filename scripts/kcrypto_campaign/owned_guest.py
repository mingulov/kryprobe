#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned-guest custody for the P8/T13 consumer campaign.

Promoted from the reviewed P2 seed (``tests/kcrypto_campaign/
owned_guest.py``, sha256 ``89699e50…`` at promotion): fresh run
dir, nonblocking exclusive flock on the common + task locks,
exact guest identity (PID + start ticks — never a PID alone),
bounded run with SIGTERM-then-SIGKILL process-group stop and
verified reap, post-run owned-absent + preexisting-unchanged
checks.

P8 extensions over the seed: the owned command identity rides
the guest record (control is never authorized through a PID
alone), ``start_guest``/``stop_guest`` write atomic spawn/stop
receipts, and :func:`run_cell` wraps one manifest portion
(start, bounded wait, stop) with those receipts. No scenario
orchestration and no oracle comparison live here — the CLI
stages the portion command, and ``reconcile``/``oracles`` judge
the collected facts.
"""

from __future__ import annotations

import fcntl
import json
import os
import pathlib
import signal
import subprocess
import time
from dataclasses import dataclass, field


class GuestError(RuntimeError):
    """Owned-guest custody failure (locks, identity, stop, or cleanup)."""


@dataclass
class OwnedGuest:
    """An owned guest lane: exact identities, held locks, live handle."""

    name: str
    run_dir: pathlib.Path
    proc: subprocess.Popen
    vng_pid: int
    vng_start_ticks: str
    preexisting_qemu: dict
    cmd: list = field(default_factory=list)
    lock_files: list = field(default_factory=list)
    lock_paths: list = field(default_factory=list)


def _atomic_write_json(path: pathlib.Path, obj: dict) -> None:
    """Write JSON atomically (tmp + fsync + rename)."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


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


def start_guest(
    *,
    vng_cmd: list[str],
    run_dir: pathlib.Path,
    name: str,
    lock_paths: list[pathlib.Path],
    console_name: str = "console.log",
) -> OwnedGuest:
    """Start one owned guest under the given locks.

    ``run_dir`` must exist and must not already hold a spawn receipt
    (fresh output per run — never reuse a run directory). Returns the
    :class:`OwnedGuest` with locks held; the caller must
    :func:`stop_guest` it. Writes the atomic ``spawn.json`` receipt
    (owned pid/start-ticks/command/locks) before returning.
    """
    run_dir = pathlib.Path(run_dir)
    if not run_dir.is_dir():
        raise GuestError(f"run dir {run_dir} does not exist (create it fresh first)")
    spawn_receipt = run_dir / "spawn.json"
    if spawn_receipt.exists():
        raise GuestError(f"run dir {run_dir} already used (refusing reuse)")
    held = acquire_locks([pathlib.Path(p) for p in lock_paths])
    try:
        before = qemu_inventory()
        console = (run_dir / console_name).open("w")
        try:
            proc = subprocess.Popen(
                vng_cmd, stdout=console, stderr=subprocess.STDOUT, start_new_session=True
            )
        finally:
            console.close()
        start_ticks = _start_ticks(proc.pid)
        _atomic_write_json(
            spawn_receipt,
            {
                "name": name,
                "vng_pid": proc.pid,
                "vng_start_ticks": start_ticks,
                "cmd": list(vng_cmd),
                "lock_paths": [str(p) for p in lock_paths],
                "preexisting_qemu_pids": sorted(before),
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
        vng_pid=proc.pid,
        vng_start_ticks=start_ticks,
        preexisting_qemu=before,
        cmd=list(vng_cmd),
        lock_files=held,
        lock_paths=[str(p) for p in lock_paths],
    )


def wait_guest(guest: OwnedGuest, timeout_s: float, poll_s: float = 1.0) -> dict:
    """Wait (bounded) for the guest command; stop it on timeout.

    Returns ``{"exit": int|None, "timed_out": bool}``. A timeout
    SIGTERMs the owned process group, escalates to SIGKILL, and
    reaps — a timed-out worker can never yield PASS (callers must
    treat ``timed_out`` as failure).
    """
    start = time.monotonic()
    while guest.proc.poll() is None:
        if time.monotonic() - start > timeout_s:
            return {"exit": _kill_group(guest), "timed_out": True}
        time.sleep(poll_s)
    return {"exit": guest.proc.wait(), "timed_out": False}


def _kill_group(guest: OwnedGuest, grace_s: float = 10.0) -> int | None:
    """SIGTERM then SIGKILL the owned process group; return exit code."""
    try:
        os.killpg(guest.proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        return guest.proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        pass
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
    """Stop (if running), reap, verify cleanup, and release locks.

    Verifies by exact identity: no remaining qemu matching the owned
    name, and every preexisting qemu PID still present with identical
    args + start ticks (a reused PID refuses the comparison — never
    authorize through a PID alone). Writes the atomic ``stop.json``
    receipt, releases locks last, and returns the stop/cleanup
    receipt fragment.
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
        "vng_exit": exit_code,
        "stopped_by_helper": stopped,
        "reaped": reaped,
        "remaining_owned_qemu": remaining,
        "preexisting_qemu_unchanged": unchanged,
        "preexisting_pid_reused": reused,
    }
    _atomic_write_json(guest.run_dir / "stop.json", fragment)
    for fh in guest.lock_files:
        fh.close()
    guest.lock_files.clear()
    return fragment


def run_cell(
    *,
    portion_id: str,
    vng_cmd: list[str],
    run_dir: pathlib.Path,
    name: str,
    lock_paths: list[pathlib.Path],
    timeout_s: float,
    console_name: str = "console.log",
) -> dict:
    """Run one manifest portion: start, bounded wait, stop.

    The portion's staged guest command (``vng_cmd``) runs under the
    owned-guest custody above with the manifest's ``timeout_s``. A
    timeout stops and reaps the owned process group and reports
    ``wait.timed_out`` — the reconciler fails such a receipt, so a
    timed-out worker can never yield PASS. Returns ``{"wait": ...,
    "stop": ...}``; ``spawn.json``/``stop.json`` land in the run
    dir beside the console log.
    """
    _ = portion_id
    guest = start_guest(
        vng_cmd=vng_cmd,
        run_dir=run_dir,
        name=name,
        lock_paths=lock_paths,
        console_name=console_name,
    )
    try:
        wait = wait_guest(guest, timeout_s)
    finally:
        stop = stop_guest(guest)
    return {"wait": wait, "stop": stop}


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
