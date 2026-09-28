#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Terminal receipts + artifact sealing for the P2 pressure cells.

Writers finalize and children are reaped BEFORE any hashing: seal
functions refuse to run while the caller still holds an open writer
it knows about (callers pass ``writers_done=True`` explicitly —
sealing is a deliberate custody step, not a side effect).

:class:`Receipt` carries the test-plan receipt groups (identity,
environment, input, observation, process, cleanup, custody) with an
explicit reason wherever a field is unavailable. :func:`verify`
is the MINIMAL verdict check for P2 (exit/timeout/reap/cleanup/
hash/expected-count gates); P8 extends it with full expected-body
equality and required/actual inventory comparison (``reconcile.py``
per the test plan). ``verify`` never launches work and never
repairs a run.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

VERDICTS = ("PASS", "FAIL", "NOT_RUN", "SUPPORTED_REFUSAL")


@dataclass
class Receipt:
    """Terminal cell receipt (test-plan receipt contract groups)."""

    schema: str = "kryprobe-pressure-receipt/v1"
    run_id: str = ""
    cell_id: str = ""
    portion_id: str = ""
    identity: dict = field(default_factory=dict)
    environment: dict = field(default_factory=dict)
    input: dict = field(default_factory=dict)
    observation: dict = field(default_factory=dict)
    process: dict = field(default_factory=dict)
    cleanup: dict = field(default_factory=dict)
    custody: dict = field(default_factory=dict)
    unavailable: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "cell_id": self.cell_id,
            "portion_id": self.portion_id,
            "identity": self.identity,
            "environment": self.environment,
            "input": self.input,
            "observation": self.observation,
            "process": self.process,
            "cleanup": self.cleanup,
            "custody": self.custody,
            "unavailable": self.unavailable,
        }


def atomic_write_json(path: Path, obj: dict) -> None:
    """Write JSON atomically (tmp + fsync + rename — readers never see a half receipt)."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    """sha256 of one artifact file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal_artifacts(run_dir: Path, names: list[str], *, writers_done: bool) -> dict[str, str]:
    """Hash the named run-dir artifacts AFTER writers stop.

    ``writers_done`` must be True (the caller finalized writers and
    reaped children first). Also writes ``SHA256SUMS`` into the run
    dir. Returns the name -> sha256 map.
    """
    if not writers_done:
        raise ValueError("seal_artifacts requires writers_done=True (finalize writers + reap children first)")
    run_dir = Path(run_dir)
    sums: dict[str, str] = {}
    for name in names:
        target = run_dir / name
        if not target.is_file():
            raise FileNotFoundError(f"seal artifact missing: {target}")
        sums[name] = sha256_file(target)
    lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items()))
    (run_dir / "SHA256SUMS").write_text(lines)
    return sums


def verify(receipt: dict) -> dict:
    """Minimal verdict check: PASS/FAIL/NOT_RUN/SUPPORTED_REFUSAL.

    Gates (any failure -> FAIL): worker exit 0, no timeout, reaped,
    no remaining owned resources, preexisting resources unchanged,
    staged/input hashes unchanged, expected == actual counts where
    both are present, every oracle check true, no named oracle
    failure (P2r/C4: a failed zero-loss gate cannot ride a clean
    receipt to PASS). A receipt declaring ``NOT_RUN``/refusal passes
    only with its required reason + positive control named. Never
    launches work, never rewrites inputs.
    """
    reasons: list[str] = []
    declared = receipt.get("verdict", "RUN")
    process = receipt.get("process", {})
    cleanup = receipt.get("cleanup", {})
    custody = receipt.get("custody", {})
    observation = receipt.get("observation", {})

    if declared in ("NOT_RUN", "SUPPORTED_REFUSAL"):
        if not receipt.get("reason"):
            reasons.append(f"{declared} without a reason")
        if not receipt.get("positive_control"):
            reasons.append(f"{declared} without a named positive control")
        verdict = declared if not reasons else "FAIL"
        return {"verdict": verdict, "reasons": reasons}

    if process.get("exit") != 0:
        reasons.append(f"worker exit {process.get('exit')!r} (want 0)")
    if process.get("timed_out"):
        reasons.append("worker timed out (a timeout cannot pass)")
    if not process.get("reaped"):
        reasons.append("worker was not reaped")
    if cleanup.get("remaining_owned"):
        reasons.append(f"owned resources remain: {cleanup['remaining_owned']!r}")
    if cleanup.get("preexisting_unchanged") is False:
        reasons.append("preexisting resources changed")
    if custody.get("hashes_unchanged") is False:
        reasons.append("staged/input hashes changed during the run")
    expected = observation.get("expected")
    actual = observation.get("actual")
    if expected is not None and actual is not None and expected != actual:
        reasons.append(f"expected {expected!r} != actual {actual!r}")
    if observation.get("omitted_loss_dimensions"):
        reasons.append(f"loss dimensions omitted: {observation['omitted_loss_dimensions']!r}")
    checks = receipt.get("checks")
    if checks is not None:
        if not isinstance(checks, dict):
            reasons.append(f"checks is not a mapping: {checks!r}")
        else:
            for name in sorted(checks):
                if checks[name] is not True:
                    reasons.append(f"oracle check failed: {name}")
    failed = receipt.get("oracle_failed")
    if failed:
        names = sorted(failed) if isinstance(failed, list) else [failed]
        reasons.append(f"oracle failures named: {names!r}")

    return {"verdict": "FAIL" if reasons else "PASS", "reasons": reasons}
