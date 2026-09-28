#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline receipt reconciliation for the P8/T13 consumer campaign.

:func:`verify_receipt` judges ONE terminal receipt; :func:`verify_receipt_file`
loads it from disk (reading only — verify never repairs a run and
never writes beside the receipt); :func:`reconcile_campaign`
judges a whole campaign directory against the manifest's required
portions.

Gates (any failure -> FAIL): the ``receipt.verify`` base gates
(worker exit 0, no timeout, reaped, no remaining owned
resources, preexisting resources unchanged, staged/input hashes
unchanged, expected == actual counts, every oracle check true,
no named oracle failure), PLUS the test-plan P8 gates:

- expected-body equality (``expected_body`` vs ``actual_body``
  deep equality — an exit-zero skip fails here);
- required/actual inventory equality (a missing required body
  and a foreign extra body both fail — aggregate totals cannot
  absorb decoys);
- staged/executed artifact-pin equality (a stale executable
  fails — the proof must be for the staged bytes);
- cleanup completeness (every required cleanup done);
- terminal flush success (a failed final flush fails).

Campaign gates: every required portion judged exactly once
(duplicates refuse), no mixed artifact pins across portions,
and every portion PASS (NOT_RUN/refusal portions pass only
with their required reason + positive control, per the base
verifier).
"""

from __future__ import annotations

import json
from pathlib import Path

from kcrypto_campaign import receipt as base

VERDICTS = ("PASS", "FAIL", "NOT_RUN", "SUPPORTED_REFUSAL")


def verify_receipt(receipt: dict) -> dict:
    """Judge one terminal receipt: PASS/FAIL/NOT_RUN/SUPPORTED_REFUSAL.

    Pure (no I/O, no launches, no rewrites). Returns ``{"verdict":
    ..., "reasons": [...]}``.
    """
    declared = receipt.get("verdict", "RUN")
    if declared in ("NOT_RUN", "SUPPORTED_REFUSAL"):
        return base.verify(receipt)
    outcome = base.verify(receipt)
    reasons = list(outcome["reasons"])

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
    actual = receipt.get("actual_bodies")
    if required is not None and actual is not None:
        missing = [b for b in required if b not in actual]
        foreign = [b for b in actual if b not in required]
        if missing:
            reasons.append(f"required bodies absent: {sorted(missing)!r}")
        if foreign:
            reasons.append(f"foreign bodies in actual inventory: {sorted(foreign)!r}")
    elif (required is None) != (actual is None):
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

    flush_ok = receipt.get("custody", {}).get("flush_ok")
    if flush_ok is False:
        reasons.append("terminal flush failed (a torn stream is never a pass)")

    return {"verdict": "FAIL" if reasons else "PASS", "reasons": reasons}


def verify_receipt_file(path: Path) -> dict:
    """Load one receipt file and judge it (read-only)."""
    return verify_receipt(json.loads(Path(path).read_text()))


def reconcile_campaign(required_portions: list[str], receipts: list[dict],
                       uniform_pins: list[str] | None = None) -> dict:
    """Judge a campaign: every required portion exactly once, pins uniform.

    Returns ``{"verdict": ..., "per_portion": {portion_id:
    verdict}, "reasons": [...]}``. Duplicate portion receipts,
    mixed executed-artifact pins across portions, missing
    portions, and any non-PASS portion verdict fail the campaign
    (NOT_RUN/SUPPORTED_REFUSAL portions are allowed only when a
    portion explicitly declares them — they still fail a
    ``required_portions`` campaign, since a required portion that
    did not run is not a pass).

    ``uniform_pins`` names the cross-portion artifacts that must
    be byte-identical everywhere (CLI, BPF objects, fixture,
    oracle). Per-portion artifacts (guest kernel config,
    per-kernel fixture module, scenario script) are pinned
    within each portion (staged == executed) but legitimately
    vary across portions; ``None`` (default) compares every pin
    strictly.
    """
    reasons: list[str] = []
    per_portion: dict[str, str] = {}
    seen: set[str] = set()
    pin_sets: dict[str, dict] = {}
    for receipt in receipts:
        portion_id = receipt.get("portion_id", "?")
        if portion_id in seen:
            reasons.append(f"duplicate portion receipt {portion_id!r}")
            continue
        seen.add(portion_id)
        judged = verify_receipt(receipt)
        per_portion[portion_id] = judged["verdict"]
        if judged["verdict"] != "PASS":
            reasons.append(f"portion {portion_id}: {judged['verdict']}: {judged['reasons']!r}")
        executed = receipt.get("executed")
        if isinstance(executed, dict):
            pin_sets[portion_id] = executed
    for portion_id in required_portions:
        if portion_id not in seen:
            reasons.append(f"required portion {portion_id!r} has no receipt")
    pinned = sorted(pin_sets)
    if len(pinned) > 1:
        def projection(pin_map: dict) -> dict:
            if uniform_pins is None:
                return pin_map
            return {name: pin_map.get(name) for name in uniform_pins}
        first = projection(pin_sets[pinned[0]])
        for portion_id in pinned[1:]:
            if projection(pin_sets[portion_id]) != first:
                reasons.append(
                    f"mixed pins: {portion_id} executed "
                    f"{projection(pin_sets[portion_id])!r} "
                    f"!= {pinned[0]} {first!r}"
                )
    return {
        "verdict": "FAIL" if reasons else "PASS",
        "per_portion": per_portion,
        "reasons": reasons,
    }
