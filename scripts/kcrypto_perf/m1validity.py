# SPDX-License-Identifier: GPL-3.0-or-later
"""M1 early-gate validity: ctx attribution rules (M1 sets only).

New module for the Task02 capture-only gate; the frozen
``validity.py``/``stats.py`` are untouched. M1 observed legs on the C
(candidate) side must carry the terminal ``ctx`` telemetry object
(live.rs ``telemetry_ctx_line``); the judge parses it fail-closed
(absence/malformation invalidates the leg — no attribution evidence,
no validity) and checks the unknown-by-difference identity plus the
per-shape exactness rules from the frozen gate protocol:

- below-capacity shapes (single, n_cgroup, churn_below): every counted
  call attributed — ``unknown == 0``, ``drops == 0``,
  ``rows == expected_rows`` exactly. (A2: frozen validity already
  reconciles driver↔sensor per-op on every overlay-reached leg, so no
  driver-oracle conjunct here — the overlay reconciles
  sensor↔attribution. The A1 ``KTOT == ops_total`` conjunct was
  arithmetically false: ``enc == ops`` AND ``dec == ops`` per §5¶1.)
- churn_full: the system ledger stays exact with all unassigned calls
  explicitly countable — ``rows == 1024``, ``unknown == drops``,
  ``unknown > 0``, present/drops readable (``present + drops ==
  system`` is then entailed, not separately pinned — A2).
- every C leg: ``system == report totals`` cross-check and a recomputed
  ``unknown == system - present`` (operands-present-but-unknown-null is
  a contradiction, distinct from an unreadable walk).

R legs carry no ``ctx`` object (expected; frozen agg equivalence only).
"""

import json
from pathlib import Path

TELEMETRY_PREFIX = "kryprobe: telemetry "
TELEMETRY_VERSION = 1

CTX_KEYS = ("rows", "present_calls", "system_calls", "unknown_calls",
            "drops")


def parse_ctx_telemetry(path: Path) -> dict:
    """Last ``{"v": 1, "ctx": {...}}`` object from a capture stderr log.

    Returns the ctx dict with exactly ``CTX_KEYS`` (ints, bools
    rejected like the frozen consumer). Raises ``ValueError`` when no
    ctx object exists or any value is mistyped/missing — the caller
    converts this to a leg-invalid reason (fail-closed).
    """
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
        ctx = obj.get("ctx")
        if isinstance(ctx, dict):
            found = ctx
    if found is None:
        raise ValueError(f"{path}: no ctx telemetry object")
    out = {}
    for key in CTX_KEYS:
        if key not in found:
            raise ValueError(f"{path}: ctx.{key} missing")
        val = found[key]
        if val is not None and (not isinstance(val, int)
                                or isinstance(val, bool)):
            raise ValueError(f"{path}: ctx.{key}={val!r} not int/null")
        out[key] = val
    return out


def check_ctx_leg(ctx: dict, totals_calls, shape: str,
                  expected_rows: int) -> list:
    """M1 ctx exactness rules for one C leg. Returns reasons (empty =
    valid). ``totals_calls`` is the report TOTALS calls (cross-check).
    No driver-oracle arithmetic (A2): kernel calls per roundtrip are
    shape- and kernel-dependent (2 flat, 4 6.12-floor, plus allocs),
    and frozen validity already reconciles driver↔sensor per-op."""
    reasons = []
    rows = ctx["rows"]
    present = ctx["present_calls"]
    system = ctx["system_calls"]
    unknown = ctx["unknown_calls"]
    drops = ctx["drops"]
    if system != totals_calls:
        reasons.append(f"ctx system={system} != report totals={totals_calls}")
    if system is not None and present is not None:
        if unknown is None:
            reasons.append(
                f"ctx contradiction: system={system} present={present} "
                "but unknown=null")
        elif unknown != system - present:
            reasons.append(
                f"ctx identity: unknown={unknown} != "
                f"system-present={system - present}")
    elif unknown is not None:
        reasons.append("ctx unknown present without both operands")
    if shape == "churn_full":
        if rows != 1024:
            reasons.append(f"churn_full rows={rows}, want exactly 1024")
        # A2: readability required; the sum-vs-oracle comparison is
        # dropped (calls-per-roundtrip is kernel/shape-dependent, and
        # present+drops==system is entailed by unknown==drops plus
        # the identity above).
        if present is None or drops is None:
            reasons.append("churn_full present/drops unreadable")
        if unknown is not None and drops is not None:
            if unknown != drops:
                reasons.append(
                    f"churn_full unknown={unknown} != drops={drops}")
        if unknown is not None and unknown <= 0:
            reasons.append(
                f"churn_full unknown={unknown}, want > 0 (saturation "
                "must show)")
    else:
        # expected_rows=None skips the row pin (6.12 diagnostic: the
        # floor splits kh across cryptd arms, so exactness without a
        # row-shape claim is the honest check).
        # A2: no present-vs-ops comparison (see the docstring —
        # frozen validity reconciles driver↔sensor per-op).
        if unknown != 0:
            reasons.append(f"{shape} unknown={unknown}, want 0")
        if drops != 0:
            reasons.append(f"{shape} drops={drops}, want 0")
        if expected_rows is not None and rows != expected_rows:
            reasons.append(
                f"{shape} rows={rows}, want exactly {expected_rows}")
    return reasons
