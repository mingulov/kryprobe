#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline receipt reconciliation + pure cell oracles for P10.

:func:`reconcile_cell` judges ONE terminal receipt (pure: no I/O,
no launches, no rewrites); :func:`reconcile_campaign` judges a
whole run directory against the required cell list. Gates (any
failure -> FAIL): worker exit 0, no timeout, reaped, no remaining
owned resources, preexisting resources unchanged, staged/input
hashes unchanged, expected == actual counts, every oracle check
true, no named oracle failure, expected/actual body equality, no
stale pins, complete cleanup, successful terminal flush. Declared
``NOT_RUN``/``UNSUPPORTED`` pass only with their required reason
plus a named positive control. A required cell that did not run
fails the campaign — no hidden NOT_RUN behind an overall PASS.

The remaining helpers are pure per-chapter oracles (Tasks 2-5):
each fails closed on fixtures a naive implementation would
mislabel (idle provider, retained handle, split I/O, same-driver
devices, queueless offload, removal-as-failover, unrelated child,
early unlock, dead/second observer, uncounted loss, silent soak
reset, unlabeled timeline arrows).
"""

from __future__ import annotations

import json
from pathlib import Path

from kcrypto_qemu_demo.receipts import SCHEMA_CELL

VERDICTS = ("PASS", "FAIL", "UNSUPPORTED", "NOT_RUN")


def reconcile_cell(receipt: dict) -> dict:
    """Judge one terminal receipt: PASS/FAIL/UNSUPPORTED/NOT_RUN.

    Returns ``{"verdict": ..., "reasons": [...]}``.
    """
    reasons: list[str] = []
    declared = receipt.get("verdict", "RUN")
    if declared in ("NOT_RUN", "UNSUPPORTED"):
        if not receipt.get("reason"):
            reasons.append(f"{declared} without a reason")
        if not receipt.get("positive_control"):
            reasons.append(f"{declared} without a named positive control")
        verdict = declared if not reasons else "FAIL"
        return {"verdict": verdict, "reasons": reasons}
    if receipt.get("$schema") != SCHEMA_CELL:
        reasons.append(f"unknown receipt schema {receipt.get('$schema')!r}")
    if not receipt.get("cell_id"):
        reasons.append("receipt without a cell_id")
    process = receipt.get("process", {})
    cleanup = receipt.get("cleanup", {})
    custody = receipt.get("custody", {})
    observation = receipt.get("observation", {})

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

    expected_body = receipt.get("expected_body")
    actual_body = receipt.get("actual_body")
    if expected_body is not None and actual_body is not None:
        if expected_body != actual_body:
            reasons.append(
                f"expected_body != actual_body: {expected_body!r} vs {actual_body!r}"
            )
    elif (expected_body is None) != (actual_body is None):
        reasons.append("expected_body/actual_body must both be present or both absent")

    required = receipt.get("required_bodies")
    actual_bodies = receipt.get("actual_bodies")
    if required is not None and actual_bodies is not None:
        missing = [b for b in required if b not in actual_bodies]
        foreign = [b for b in actual_bodies if b not in required]
        if missing:
            reasons.append(f"required bodies absent: {sorted(missing)!r}")
        if foreign:
            reasons.append(f"foreign bodies in actual inventory: {sorted(foreign)!r}")
    elif (required is None) != (actual_bodies is None):
        reasons.append("required_bodies/actual_bodies must both be present or both absent")

    pins = receipt.get("pins")
    executed = receipt.get("executed")
    if pins is not None and executed is not None:
        for name in sorted(set(pins) | set(executed)):
            staged, ran = pins.get(name), executed.get(name)
            if staged is None:
                reasons.append(f"artifact {name!r} executed but never staged")
            elif ran is None:
                reasons.append(f"artifact {name!r} staged but missing from executed pins")
            elif staged != ran:
                reasons.append(
                    f"artifact {name!r} stale: staged {staged!r} != executed {ran!r}"
                )
    elif (pins is None) != (executed is None):
        reasons.append("pins/executed must both be present or both absent")

    cleanup_required = receipt.get("cleanup_required")
    cleanup_done = receipt.get("cleanup_done")
    if cleanup_required is not None and cleanup_done is not None:
        missing_cleanup = [c for c in cleanup_required if c not in cleanup_done]
        if missing_cleanup:
            reasons.append(f"cleanup missing: {sorted(missing_cleanup)!r}")
    elif (cleanup_required is None) != (cleanup_done is None):
        reasons.append("cleanup_required/cleanup_done must both be present or both absent")

    if custody.get("flush_ok") is False:
        reasons.append("terminal flush failed (a torn stream is never a pass)")

    return {"verdict": "FAIL" if reasons else "PASS", "reasons": reasons}


def verify_receipt_file(path: Path) -> dict:
    """Load one receipt file and judge it (read-only)."""
    return reconcile_cell(json.loads(Path(path).read_text()))


def reconcile_campaign(
    required_cells: list[str],
    receipts: list[dict],
    uniform_pins: list[str] | None = None,
) -> dict:
    """Judge a campaign: every required cell exactly once, pins uniform.

    Returns ``{"verdict": ..., "per_cell": {...}, "reasons": [...]}``.
    Duplicate cell receipts, mixed executed-artifact pins across
    cells, missing cells, and any non-PASS cell verdict fail the
    campaign. ``uniform_pins`` names the cross-cell artifacts that
    must be byte-identical everywhere (product CLI/BPF); per-cell
    artifacts (guest kernel images) are pinned within each cell but
    legitimately vary across cells; ``None`` compares every pin.
    """
    reasons: list[str] = []
    per_cell: dict[str, str] = {}
    seen: set[str] = set()
    pin_sets: dict[str, dict] = {}
    for receipt in receipts:
        cell_id = receipt.get("cell_id", "?")
        if cell_id in seen:
            reasons.append(f"duplicate cell receipt {cell_id!r}")
            continue
        seen.add(cell_id)
        judged = reconcile_cell(receipt)
        per_cell[cell_id] = judged["verdict"]
        if judged["verdict"] != "PASS":
            reasons.append(f"cell {cell_id}: {judged['verdict']}: {judged['reasons']!r}")
        executed = receipt.get("executed")
        if isinstance(executed, dict):
            pin_sets[cell_id] = executed
    for cell_id in required_cells:
        if cell_id not in seen:
            reasons.append(f"required cell {cell_id!r} has no receipt")
    pinned = sorted(pin_sets)
    if len(pinned) > 1:

        def projection(pin_map: dict) -> dict:
            if uniform_pins is None:
                return pin_map
            return {name: pin_map.get(name) for name in uniform_pins}

        first = projection(pin_sets[pinned[0]])
        for cell_id in pinned[1:]:
            if projection(pin_sets[cell_id]) != first:
                reasons.append(
                    f"mixed pins: {cell_id} executed "
                    f"{projection(pin_sets[cell_id])!r} "
                    f"!= {pinned[0]} {first!r}"
                )
    return {
        "verdict": "FAIL" if reasons else "PASS",
        "per_cell": per_cell,
        "reasons": reasons,
    }


# --- Task 2 (D01-D03) pure oracles --------------------------------------


def provider_usage(registry: list[str], used: list[str]) -> dict:
    """Split the algorithm registry into used vs available-only providers.

    A registered but unused provider stays "available", never "used".
    """
    used_set = set(used)
    return {
        "used": [driver for driver in registry if driver in used_set],
        "available_only": [driver for driver in registry if driver not in used_set],
    }


def fresh_vs_retained(alloc_events: list[dict]) -> dict:
    """Split allocation events into fresh lifetime IDs vs retained reuses.

    Each event is ``{"alloc_id": str, "reused": bool}``. A retained
    handle must not count as a fresh selection.
    """
    fresh: list[str] = []
    retained: list[str] = []
    for event in alloc_events:
        if event.get("reused"):
            retained.append(event["alloc_id"])
        else:
            fresh.append(event["alloc_id"])
    return {"fresh_ids": fresh, "retained_ids": retained}


def split_counts(io_bytes_total: int, api_fragments: list[int]) -> dict:
    """Reconcile one I/O in bytes and its API calls as separate populations."""
    return {"io_bytes": io_bytes_total, "api_calls": len(api_fragments)}


# --- Task 3 (D04-D06) pure oracles --------------------------------------


def identify_device(driver_rows: list[dict], queue_rows: list[dict]) -> dict:
    """Identify the serving device, or "unknown" without queue evidence.

    Equal driver strings never identify a particular device; exactly
    one queue binding names it.
    """
    drivers = {row.get("driver") for row in driver_rows}
    if len(driver_rows) > 1 and len(drivers) == 1 and not queue_rows:
        return {"device": "unknown", "reason": "same driver on several devices"}
    if len(queue_rows) == 1 and queue_rows[0].get("dev"):
        return {"device": queue_rows[0]["dev"], "reason": "queue-bound"}
    if not queue_rows:
        return {"device": "unknown", "reason": "no queue evidence"}
    return {"device": "unknown", "reason": "ambiguous queue bindings"}


def is_offload(selected_driver: str, queue_proof: dict | None) -> bool:
    """True only with a bound device+queue proof — selection alone is not offload."""
    _ = selected_driver
    return bool(
        isinstance(queue_proof, dict)
        and queue_proof.get("dev")
        and queue_proof.get("queue") is not None
        and queue_proof.get("bound") is True
    )


def removal_outcome(removal_event: dict, fresh_alloc: dict) -> dict:
    """Record a device-removal observation without implying retry/failover."""
    driver = fresh_alloc.get("driver")
    errno = fresh_alloc.get("errno")
    if driver is not None:
        observed = f"reselected:{driver}"
    elif errno is not None:
        observed = f"refused:errno={errno}"
    else:
        observed = "unfinished"
    return {
        "implies_retry": False,
        "implies_failover": False,
        "quiesced": bool(removal_event.get("quiesced")),
        "qmp_event": bool(removal_event.get("qmp_event")),
        "observed": observed,
    }


def fallback_relation(parent_rows: list[dict], child_rows: list[dict], proof) -> dict:
    """Name a parent/child fallback relation only with a binding proof."""
    _ = (parent_rows, child_rows)
    if isinstance(proof, dict) and proof.get("parent") and proof.get("child"):
        return {"relation": "proved", "proof": proof}
    return {"relation": "unknown", "proof": None}


def check_x01_threshold(cases: list[dict], expected: dict[int, str]) -> dict:
    """Judge the controlled X01 threshold fixture: 100 ops per size."""
    reasons: list[str] = []
    seen: set[int] = set()
    for case in cases:
        size = case.get("size")
        seen.add(size)
        want = expected.get(size)
        if want is None:
            reasons.append(f"size {size!r} outside the fixture contract")
            continue
        if case.get("path") != want:
            reasons.append(f"size {size}: path {case.get('path')!r} != {want!r}")
        if case.get("ops") != 100:
            reasons.append(f"size {size}: ops {case.get('ops')!r} != 100")
    for size in sorted(expected):
        if size not in seen:
            reasons.append(f"size {size} missing from the run")
    return {"verdict": not reasons, "reasons": reasons}


# --- Task 4 (D07) pure oracles -------------------------------------------


def unlock_after_attach(attach_ready_ts: float | None, unlock_ts: float | None) -> bool:
    """True iff attach-ready exists and the unlock strictly follows it."""
    return (
        attach_ready_ts is not None
        and unlock_ts is not None
        and unlock_ts > attach_ready_ts
    )


def unobserved_interval(boot_ts: float, attach_ts: float | None) -> dict:
    """Mark the pre-attach boot interval UNOBSERVED (bounded iff attached)."""
    if attach_ts is None:
        return {"mark": "UNOBSERVED", "start": boot_ts, "end": None, "bounded": False}
    return {"mark": "UNOBSERVED", "start": boot_ts, "end": attach_ts, "bounded": True}


def single_observer(collectors: list[dict]) -> bool:
    """True iff exactly one collector is alive with preserved descriptors."""
    alive = [
        collector
        for collector in collectors
        if collector.get("alive") and collector.get("fds_preserved")
    ]
    return len(alive) == 1 and len([c for c in collectors if c.get("alive")]) == 1


# --- Task 5 (D08) pure oracles -------------------------------------------


def loss_visible(loss: dict) -> bool:
    """True iff loss is explicitly counted (a missing count is not zero loss)."""
    return "dropped" in loss and isinstance(loss.get("dropped"), int) and "omitted" in loss


def soak_windows(windows: list[dict]) -> dict:
    """Judge soak windows: every window capped, no silent reset."""
    reasons: list[str] = []
    for window in windows:
        if not window.get("capped"):
            reasons.append(f"window {window.get('id', '?')!r} is uncapped")
        if window.get("reset") == "silent":
            reasons.append(f"window {window.get('id', '?')!r} restarted silently")
    return {"ok": not reasons, "reasons": reasons}


TIMELINE_LABELS = frozenset({"observed", "reference", "inferred", "unknown"})


def timeline_edges(edges: list[dict]) -> dict:
    """Judge timeline arrows: every edge needs a known label + run ID."""
    reasons: list[str] = []
    for edge in edges:
        if edge.get("label") not in TIMELINE_LABELS:
            reasons.append(f"edge {edge.get('frm')}->{edge.get('to')} has no proved label")
        if not edge.get("run_id"):
            reasons.append(f"edge {edge.get('frm')}->{edge.get('to')} has no run ID")
    return {"ok": not reasons, "reasons": reasons}
