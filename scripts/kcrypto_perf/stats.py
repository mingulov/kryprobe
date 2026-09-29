#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T14 perf statistics: percentiles, roundtrips, ratios, set verdicts.

Frozen definitions (see docs/bench-thresholds.md P9 section):
percentiles are nearest-rank over the preserved measurement rows;
workload latency is the driver per-op roundtrip; set verdicts need
the median inside the budget and at least 80% of pairs inside
(4/5 at the minimum five pairs). Outliers are never dropped.
"""

from __future__ import annotations


def percentile(values: list, pct: float) -> float:
    """Nearest-rank percentile (pct in (0, 100])."""
    if not values:
        raise ValueError("percentile of empty population")
    if not 0 < pct <= 100:
        raise ValueError(f"bad percentile {pct}")
    ordered = sorted(values)
    rank = (len(ordered) * pct + 99) // 100
    rank = max(1, min(rank, len(ordered)))
    return ordered[int(rank) - 1]


def median(values: list) -> float:
    """Median (mean of the two middles for even n)."""
    if not values:
        raise ValueError("median of empty population")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def roundtrip_latencies(rows: list, cls: str) -> list:
    """Per-op workload latency in ns from ledger rows.

    AF_ALG classes pair encrypt+decrypt call rows by seq (the two
    calls are contiguous, so the sum is the exact roundtrip);
    async GO rows are already per-op. Unpaired or misclassed rows
    raise — never a silent partial pairing.
    """
    if cls == "async":
        out = []
        for seq, _phase, op, dt in rows:
            if op != "go":
                raise ValueError(f"async row seq={seq} has op={op!r}")
            out.append(dt)
        return out
    if cls not in ("skcipher", "aead"):
        raise ValueError(f"unknown workload class {cls!r}")
    by_seq: dict = {}
    for seq, _phase, op, dt in rows:
        if op not in ("encrypt", "decrypt"):
            raise ValueError(f"{cls} row seq={seq} has op={op!r}")
        slot = by_seq.setdefault(seq, {})
        if op in slot:
            raise ValueError(f"duplicate {op} row seq={seq}")
        slot[op] = dt
    out = []
    for seq in sorted(by_seq):
        slot = by_seq[seq]
        if set(slot) != {"encrypt", "decrypt"}:
            raise ValueError(f"unpaired rows seq={seq}: {sorted(slot)}")
        out.append(slot["encrypt"] + slot["decrypt"])
    return out


def throughput(ops: int, window_s: float) -> float:
    """Operations per second over the measured window."""
    if window_s <= 0:
        raise ValueError(f"non-positive window {window_s}")
    return ops / window_s


def set_verdict(ratios: list, lo: float | None, hi: float | None) -> str:
    """Frozen P9 set verdict: PASS / FAIL / INCONCLUSIVE.

    PASS needs the median inside [lo, hi] and at least 80% of the
    pairs inside; FAIL needs the median outside and at least 80%
    outside; anything else (including fewer than five pairs) is
    INCONCLUSIVE — spread too wide for the sample, reported as-is.
    """
    if lo is None and hi is None:
        raise ValueError("set_verdict needs at least one bound")
    if len(ratios) < 5:
        return "INCONCLUSIVE"

    def inside(ratio):
        return (lo is None or ratio >= lo) and (hi is None or ratio <= hi)

    med = median(list(ratios))
    frac = sum(1 for r in ratios if inside(r)) / len(ratios)
    if inside(med) and frac >= 0.8:
        return "PASS"
    if not inside(med) and frac <= 0.2:
        return "FAIL"
    return "INCONCLUSIVE"
