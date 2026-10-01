#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T14 leg/pair/set validity judges (frozen P9 rules).

Observed legs must reconcile EXACTLY with their driver ledger
(per-kernel equivalence pinned by preflight), carry zero
unexpected loss, and exit rc 0/3 with an rc-0 driver. Details
legs that truncate are envelope data points, never valid pair
legs; async details legs are envelope-only (terminals unknown).
"""

from __future__ import annotations

VALID_CAPTURE_RC = (0, 3)

UNEXPECTED_LOSS = (
    "ktot_gap",
    "ring_drops",
    "overflow_identities",
    "predrop_cfg_fail",
    "predrop_fret_fail",
    "predrop_arg_null",
    "predrop_chase_fail",
    "predrop_name_fail",
    "predrop_spare_6",
    "predrop_spare_7",
)

FLOOR_ARMS = ("cbc-aes-aesni", "__cbc-aes-aesni")

AFALG_CLASSES = ("P-64", "P-4K", "P-1M", "P-AEAD")
AFALG_FAMILY = {"P-64": "skcipher", "P-4K": "skcipher", "P-1M": "skcipher",
                "P-AEAD": "aead"}


def _loss_reasons(loss: dict, destroy_skip) -> list:
    reasons = []
    for name in UNEXPECTED_LOSS:
        if loss.get(name):
            reasons.append(f"loss {name}={loss.get(name)}")
    if destroy_skip is not None and \
            loss.get("predrop_destroy_skip") != destroy_skip:
        reasons.append("loss predrop_destroy_skip="
                       f"{loss.get('predrop_destroy_skip')} "
                       f"want {destroy_skip}")
    return reasons


def check_leg_agg(parsed: dict, summary: dict, kernel: str, cls: str,
                  capture_rc: int, expected_alloc: int = 1,
                  pin_destroy: bool = True) -> dict:
    """Judge one aggregation-mode observed leg.

    ``expected_alloc`` is 1 for single-socket legs and the thread
    count for many-submitter probe legs (one alloc per worker
    socket). ``pin_destroy`` is False for probe legs, where
    destroy-skip scaling is unverified (recorded, not judged).
    """
    reasons = []
    ops = summary.get("ops_total")
    if summary.get("rc") != 0:
        reasons.append(f"driver rc={summary.get('rc')}")
    if summary.get("timed_out"):
        reasons.append("driver timed out")
    if capture_rc not in VALID_CAPTURE_RC:
        reasons.append(f"capture rc={capture_rc}")
    if cls == "P-ASYNC":
        reasons.extend(_check_async_counts(parsed, ops))
        reasons.extend(_loss_reasons(parsed.get("loss", {}), ops))
    elif cls in AFALG_CLASSES:
        family = AFALG_FAMILY[cls]
        if kernel == "6.12.111":
            reasons.extend(_check_floor_counts(parsed, ops, family))
            # R1 manifest v3 pins floor destroy_skip == 3 in
            # advance (P9 sealed 10/10 + rejudge-verified;
            # P9R1O-N2 left it unjudged because the P9
            # manifest named no pin — the R1 manifest does).
            reasons.extend(_loss_reasons(parsed.get("loss", {}),
                                         FLOOR_DESTROY_PIN))
        else:
            reasons.extend(_check_flat_counts(parsed, ops, family,
                                              expected_alloc))
            reasons.extend(_loss_reasons(
                parsed.get("loss", {}),
                expected_alloc if pin_destroy else None))
    else:
        reasons.append(f"unknown class {cls}")
    return {"valid": not reasons, "reasons": reasons,
            "outcome": "valid" if not reasons else "invalid"}


def _check_flat_counts(parsed: dict, ops: int, family: str,
                       expected_alloc: int = 1) -> list:
    reasons = []
    for op in ("encrypt", "decrypt"):
        matches = [(key, row) for key, row in parsed.get("agg", {}).items()
                   if key[0] == family and key[1] == op]
        if len(matches) != 1:
            reasons.append(f"{family} {op}: {len(matches)} rows, want 1")
            continue
        row = matches[0][1]
        if row.get("calls") != ops:
            reasons.append(f"{family} {op} calls={row.get('calls')} "
                           f"want {ops}")
        if row.get("errors"):
            reasons.append(f"{family} {op} errors={row.get('errors')}")
        if row.get("queued"):
            reasons.append(f"{family} {op} queued={row.get('queued')}")
    allocs = parsed.get("alloc_rows", [])
    total_alloc = sum(a.get("calls", 0) for a in allocs)
    if total_alloc != expected_alloc:
        reasons.append(f"alloc total={total_alloc} want {expected_alloc}")
    return reasons


def _check_floor_counts(parsed: dict, ops: int, family: str) -> list:
    reasons = []
    for op in ("encrypt", "decrypt"):
        for arm in FLOOR_ARMS:
            row = parsed.get("agg", {}).get((family, op, arm))
            if row is None:
                reasons.append(f"{family} {op} {arm}: row missing")
            elif row.get("calls") != ops:
                reasons.append(f"{family} {op} {arm} calls="
                               f"{row.get('calls')} want {ops}")
    algos = sorted(a.get("algorithm") for a in parsed.get("alloc_rows", []))
    if algos != ["cbc(aes)", "cryptd(__cbc-aes-aesni)"]:
        reasons.append(f"floor alloc algorithms={algos}")
    for alloc in parsed.get("alloc_rows", []):
        if alloc.get("calls") != 1:
            reasons.append(f"floor alloc calls={alloc.get('calls')}")
    return reasons


def _check_async_counts(parsed: dict, gos: int) -> list:
    reasons = []
    rows = [(key, row) for key, row in parsed.get("agg", {}).items()
            if key[0] == "skcipher" and key[1] == "encrypt"]
    if len(rows) != 1:
        reasons.append(f"async encrypt rows={len(rows)}, want 1")
        return reasons
    row = rows[0][1]
    if row.get("calls") != gos:
        reasons.append(f"async calls={row.get('calls')} want {gos}")
    if row.get("ok") != 0:
        reasons.append(f"async ok={row.get('ok')} want 0 (EINPROGRESS)")
    if row.get("queued") != gos:
        reasons.append(f"async queued={row.get('queued')} want {gos}")
    if row.get("errors"):
        reasons.append(f"async errors={row.get('errors')}")
    allocs = parsed.get("alloc_rows", [])
    if len(allocs) != 1 or allocs[0].get("calls") != gos:
        reasons.append("async alloc="
                       f"{[a.get('calls') for a in allocs]} want [{gos}]")
    return reasons


# R1 pre-pinned detail rule (manifest details_clean, frozen before
# the first R1 sampling boot): these receipt-loss keys are bounded
# FIFO maintenance, not lost observations — tolerated (recorded in
# `tolerated`, never silent). Any other loss key still invalidates.
TOLERATED_DETAIL_LOSS = frozenset({"adapter.tombstone_evictions"})

# R1 manifest v3 floor pin (equivalence.floor_afalg): the nested
# floor route destroys 3 transforms per socket-close (P9 sealed
# 10/10 + floor-rejudge verified). Pinned in advance, judged.
FLOOR_DESTROY_PIN = 3


def check_leg_details(parsed: dict, expected_calls: int, cls: str) -> dict:
    """Judge one details-mode observed leg.

    Outcomes: valid (clean, exact), truncated (hit the detail
    bound: envelope data point), envelope (async: submits covered,
    terminals unknown), invalid (anything else — counted loss,
    short emit, unfinished sync work).
    """
    receipt = parsed.get("receipt", {})
    loss = receipt.get("loss", {}) or {}
    reasons = []
    tolerated = {k: v for k, v in loss.items()
                 if k in TOLERATED_DETAIL_LOSS}
    hard_loss = {k: v for k, v in loss.items()
                 if k not in TOLERATED_DETAIL_LOSS}
    emitted = receipt.get("emitted")
    at_cap = (isinstance(emitted, int) and emitted >= 100000
              and emitted < expected_calls)
    if receipt.get("truncated") or at_cap:
        return {"valid": False, "outcome": "truncated",
                "tolerated": tolerated,
                "reasons": ["detail bound hit: "
                            f"obs={parsed.get('observations')} "
                            f"emitted={emitted} offered={expected_calls}"]}
    if hard_loss:
        reasons.append(f"detail loss={hard_loss}")
    if parsed.get("observations") != expected_calls:
        reasons.append(f"detail obs={parsed.get('observations')} "
                       f"want {expected_calls}")
    if receipt.get("emitted") != receipt.get("admitted"):
        reasons.append(f"emitted={receipt.get('emitted')} admitted="
                       f"{receipt.get('admitted')}")
    if cls == "P-ASYNC":
        return {"valid": False, "outcome": "envelope",
                "tolerated": tolerated,
                "reasons": reasons + [
                    "async terminals unknown: "
                    f"unfinished={receipt.get('unfinished')} "
                    f"terms={parsed.get('terminals')}"]}
    if receipt.get("unfinished"):
        reasons.append(f"unfinished={receipt.get('unfinished')}")
    if reasons:
        return {"valid": False, "outcome": "invalid",
                "tolerated": tolerated, "reasons": reasons}
    return {"valid": True, "outcome": "valid",
            "tolerated": tolerated, "reasons": []}


def check_quiet(totals: dict) -> dict:
    """A boot quiet leg must observe zero calls."""
    calls = totals.get("calls")
    if calls != 0:
        return {"valid": False,
                "reasons": [f"quiet leg calls={calls}, want 0"]}
    return {"valid": True, "reasons": []}


def check_pair(valid_a: bool, valid_b: bool) -> dict:
    """A pair is valid iff both legs are valid."""
    valid = bool(valid_a and valid_b)
    return {"valid": valid,
            "reasons": [] if valid else ["a leg is invalid"]}


def check_set(pair_valid: list) -> dict:
    """A pair-set is qualified with >= 5 valid pairs (order kept)."""
    valid_pairs = sum(1 for valid in pair_valid if valid)
    qualified = valid_pairs >= 5
    return {"qualified": qualified, "valid_pairs": valid_pairs,
            "attempted_pairs": len(pair_valid)}
