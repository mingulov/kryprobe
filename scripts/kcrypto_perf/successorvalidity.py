# SPDX-License-Identifier: GPL-3.0-or-later
"""Successor-epoch exactness operands (freeze Amendment A12).

Workspace ADR-0021 replaces the frozen ``observed == truth``
rule for a fresh successor epoch on the task-06 fixed bytes
(``d151128``, product ADR-0013): BPF trampoline guard skips are
kernel delivery loss the product measures exactly but cannot
prevent (FORENSICS-2: 51/51 legs reconcile as truth - observed
= misses), so the successor judge requires, per observed leg,

    observed + kernel misses == driver truth     (exact, no
    tolerance), report misses == stderr miss delta, and
    ktot_gap == 0 over the per-program lanes (9 KTOT /
    KCTLCOUNT / KCTX_DROPS slots, 72 KDROPS lanes, folded by
    the product; the lane count surfaces here as the miss
    telemetry ``programs`` operand).

This module only drafts the operands (Task07 phase 1): strict
parsers for the fixed-bytes miss surfaces the frozen parser
does not expose (``kernel_misses`` / snapshot counters in
api-returns coverage, the terminal miss telemetry line) and
pure per-leg checkers. The frozen ``parsers.py`` /
``validity.py`` and the M1 ``m1validity.py`` rules are
untouched, sealed cells are never re-judged, and wiring into
the campaign judge waits for the A12 declaration. Mid-run
bpftool map dumps stay localizer evidence, never operands.
"""

import json
from pathlib import Path

TELEMETRY_PREFIX = "kryprobe: telemetry "
TELEMETRY_VERSION = 1

_U64_MAX = 2 ** 64 - 1

SNAPSHOT_COUNTERS = ("snapshot_agg_calls", "snapshot_totals_calls",
                     "ktot_gap")


def _unsigned_counter(value):
    """Strict unsigned counter (twin of m1validity's): a real
    int in u64 range (bools are not counters) or a digit string
    (serde JSON form); anything else is mistyped evidence."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= _U64_MAX else None
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        return parsed if parsed <= _U64_MAX else None
    return None


def _is_counter(value) -> bool:
    return _unsigned_counter(value) is not None


def _report_counters(path: Path, dim: str) -> list:
    try:
        doc = json.loads(Path(path).read_text())
    except OSError as err:
        raise ValueError(f"cannot read {path}: {err}") from err
    except ValueError as err:
        raise ValueError(f"bad JSON in {path}: {err}") from err
    try:
        counters = doc["coverage"][dim]["counters"]
    except (KeyError, TypeError) as err:
        raise ValueError(f"{path}: no {dim} counters: {err}") from err
    if not isinstance(counters, list):
        raise ValueError(f"{path}: {dim} counters not a list: "
                         f"{counters!r}")
    return counters


def _named_counter(path: Path, dim: str, name: str) -> int:
    found = None
    for entry in _report_counters(path, dim):
        if not isinstance(entry, dict):
            continue
        if entry.get("name") == name:
            if found is not None:
                raise ValueError(
                    f"{path}: duplicate {name} counter entries")
            value = _unsigned_counter(entry.get("value"))
            if value is None:
                raise ValueError(
                    f"{path}: bad {name} counter "
                    f"{entry.get('value')!r}")
            found = value
    if found is None:
        raise ValueError(f"{path}: {name} counter missing")
    return found


def parse_kernel_misses_counter(path: Path) -> int:
    """``kernel_misses`` from a sealed api-returns report's
    ``coverage.aggregate_counts.counters`` (fixed bytes only;
    pre-fix reports lack the counter and refuse — the caller
    converts this to a leg-invalid reason, fail-closed)."""
    return _named_counter(path, "aggregate_counts", "kernel_misses")


def parse_snapshot_counters(path: Path) -> dict:
    """End-of-run snapshot operands (``snapshot_agg_calls``,
    ``snapshot_totals_calls``, ``ktot_gap``) under the same
    strict extraction; any missing/mistyped operand refuses
    (pre-fix reports without ``ktot_gap`` included)."""
    return {name: _named_counter(path, "aggregate_counts", name)
            for name in SNAPSHOT_COUNTERS}


def _telemetry_int(value, path: Path, what: str) -> int:
    """Telemetry operands are bare JSON ints (live.rs
    ``telemetry_miss_line``); bools/strings/floats refuse."""
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= _U64_MAX:
        raise ValueError(f"{path}: misses.{what}={value!r} not "
                         "an unsigned int")
    return value


def parse_miss_telemetry(path: Path) -> dict:
    """Last ``{"v": 1, "misses": {...}}`` terminal object from a
    capture stderr log (printed for workload and, on fixed
    bytes, api-returns legs). Returns ``programs`` (attached
    program count — the per-program lane surface, 9 on the
    kcrypto spine), ``miss_delta``, and ``run_delta`` (int or
    None). An ``unavailable`` terminal, a missing line, or any
    mistyped operand raises ``ValueError`` — fail-closed,
    never a zero-filled miss count."""
    try:
        text = Path(path).read_text()
    except OSError as err:
        raise ValueError(f"cannot read {path}: {err}") from err
    found = None
    for raw in text.splitlines():
        if not raw.startswith(TELEMETRY_PREFIX):
            continue
        try:
            obj = json.loads(raw[len(TELEMETRY_PREFIX):])
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("v") != TELEMETRY_VERSION:
            continue
        misses = obj.get("misses")
        if isinstance(misses, dict):
            found = misses
    if found is None:
        raise ValueError(f"{path}: no miss telemetry object")
    if found.get("unavailable") is True:
        raise ValueError(f"{path}: miss terminal unavailable")
    for key in ("programs", "miss_delta", "run_delta"):
        if key not in found:
            raise ValueError(f"{path}: misses.{key} missing")
    programs = _telemetry_int(found["programs"], path, "programs")
    if programs == 0:
        raise ValueError(f"{path}: misses.programs=0 (no lane "
                         "surface — mistyped evidence)")
    run_delta = found["run_delta"]
    if run_delta is not None:
        run_delta = _telemetry_int(run_delta, path, "run_delta")
    return {"programs": programs,
            "miss_delta": _telemetry_int(found["miss_delta"], path,
                                          "miss_delta"),
            "run_delta": run_delta}


def successor_truth(*, ops: int, alloc: int, kernel: str) -> int:
    """Per-leg driver-truth oracle for the successor equation.

    Flat kernels (7.x): one encrypt + one decrypt per roundtrip
    plus the expected alloc population (1 single-socket, thread
    count for many-submitter legs — the n_cgroup form
    2*ops_total + actors is FORENSICS-2/K6 proven). The 6.12
    floor splits each op across two arms and pins 2 allocs
    (same row arithmetic as the frozen floor checker). Unknown
    kernels refuse — no invented oracle."""
    if not _is_counter(ops) or not _is_counter(alloc):
        raise ValueError(f"successor truth operands unreadable: "
                         f"ops={ops!r} alloc={alloc!r}")
    if kernel == "6.12.111":
        return 4 * ops + 2
    if kernel in ("7.0.14", "7.2.6"):
        return 2 * ops + alloc
    raise ValueError(f"successor truth: unknown kernel {kernel!r}")


def exact_count_claim(misses) -> bool:
    """A leg may claim exact counts only when its measured
    kernel misses are exactly 0 (product ADR-0013); measured
    nonzero misses are exact-accounted, never exact-counted,
    and an unreadable operand claims nothing."""
    return _unsigned_counter(misses) == 0


def check_successor_leg(*, observed, truth, report_misses=None,
                        stderr_miss_delta=None, ktot_gap=None,
                        programs=None, expected_programs=None) -> list:
    """Successor exactness for one observed leg (A12 items 1-2).
    Returns reasons (empty = exact-accounted). Every operand
    must be a readable unsigned counter — None/mistyped is
    invalid, never skipped or coerced. ``observed`` is the
    terminal total the report stands behind (report totals /
    ctx system / ledger system_total per mode), ``truth`` the
    per-leg driver expectation supplied by the caller's oracle
    (e.g. n_cgroup: 2*ops_total + expected_alloc). At least one
    miss surface must be present; when both are, they must
    agree exactly. ``ktot_gap`` is a required operand: the
    sealed counter on api-returns legs, the same-walk
    present-minus-system difference on M legs."""
    reasons = []
    for name, value in (("observed", observed), ("truth", truth)):
        if not _is_counter(value):
            reasons.append(f"successor {name} unreadable: {value!r}")
    for name, value in (("report_misses", report_misses),
                        ("stderr_miss_delta", stderr_miss_delta)):
        if value is not None and not _is_counter(value):
            reasons.append(f"successor {name} unreadable: {value!r}")
    if reasons:
        return reasons
    if report_misses is None and stderr_miss_delta is None:
        reasons.append("successor kernel misses unreadable: no "
                       "report counter and no miss telemetry")
    elif report_misses is not None and stderr_miss_delta is not None \
            and report_misses != stderr_miss_delta:
        reasons.append(f"successor misses disagree: report="
                       f"{report_misses} != stderr={stderr_miss_delta}")
    misses = report_misses if report_misses is not None \
        else stderr_miss_delta
    if misses is not None and observed + misses != truth:
        reasons.append(f"successor truth equation: observed={observed} "
                       f"+ misses={misses} != truth={truth} "
                       f"(residual {truth - observed - misses})")
    if not _is_counter(ktot_gap):
        reasons.append(f"successor ktot_gap unreadable: {ktot_gap!r}")
    elif ktot_gap != 0:
        reasons.append(f"successor ktot_gap={ktot_gap}, want 0 "
                       "(per-program lane contradiction)")
    if expected_programs is not None:
        if not _is_counter(programs) or programs == 0:
            reasons.append(f"successor programs unreadable: {programs!r}")
        elif programs != expected_programs:
            reasons.append(f"successor programs={programs}, want "
                           f"{expected_programs} (lane surface pin)")
    elif programs is not None and (not _is_counter(programs)
                                   or programs == 0):
        reasons.append(f"successor programs unreadable: {programs!r}")
    return reasons


def check_successor_m_leg(parsed: dict, ctx: dict, *, miss_delta,
                          truth, programs=None,
                          expected_programs=None) -> list:
    """M-leg truth check (A12 item 3): the workload ledger
    ``system_total`` is the observed operand, the stderr miss
    delta the miss operand (workload-json carries no miss
    field), and the same-walk ktot_gap operand is ctx
    ``present_calls`` - ``system_total`` (Sigma-KCTX vs the
    KTOT walk, the FORENSICS-2 lag definition). The ctx
    ``system_calls`` cross-check is repeated here so the
    wrapper is honest standalone; ``check_m_cross`` remains
    the campaign judge's full same-walk gate."""
    reasons = []
    system_total = parsed["ledger"]["system_total"]
    if ctx["system_calls"] != system_total:
        reasons.append("successor M cross contradiction: ctx."
                       f"system_calls={ctx['system_calls']} != ledger."
                       f"system_total={system_total}")
    present = ctx["present_calls"]
    if _is_counter(present) and _is_counter(system_total):
        ktot_gap = present - system_total
        if ktot_gap < 0:
            reasons.append("successor M ktot_gap operand: present="
                           f"{present} < system_total={system_total} "
                           "(negative lane gap — contradiction)")
            ktot_gap = None
    else:
        ktot_gap = None
    reasons.extend(check_successor_leg(
        observed=system_total, truth=truth,
        stderr_miss_delta=miss_delta, ktot_gap=ktot_gap,
        programs=programs, expected_programs=expected_programs))
    return reasons
