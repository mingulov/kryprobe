#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned-guest helper for the P2 pressure cells (minimal P8 seed).

Reuses the T07 ``run-vng.py`` custody mechanisms: fresh run dir,
nonblocking exclusive flock on the common + task locks, exact
guest identity (PID + start ticks — never a PID alone), bounded
run with SIGTERM-then-SIGKILL process-group stop and verified
reap, post-run owned-absent + preexisting-unchanged checks.

This is NOT the full P8 harness: no scenario orchestration, no
in-guest driver, no oracle comparison. P8 extension points are
marked ``P8:`` below (``run_cell`` per scenario, full receipt
verifier with expected/actual inventory comparison).
"""

from __future__ import annotations

import fcntl
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
    :func:`stop_guest` it (P8: ``run_cell`` wraps start/stop per
    scenario with scenario-specific argv + timeouts from the manifest).
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
    authorize through a PID alone). Releases locks last. Returns the
    stop/cleanup receipt fragment.
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
    for fh in guest.lock_files:
        fh.close()
    guest.lock_files.clear()
    return {
        "vng_exit": exit_code,
        "stopped_by_helper": stopped,
        "reaped": reaped,
        "remaining_owned_qemu": remaining,
        "preexisting_qemu_unchanged": unchanged,
        "preexisting_pid_reused": reused,
    }


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
