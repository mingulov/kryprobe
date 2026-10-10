#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T14 perf parsers: api-returns reports, lifecycle jsonl, ledgers, sampler.

Shapes follow the product output observed in T14 preflight. Every
parse failure raises :class:`ParseError` (loud, never a partial
parse passed downstream).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


class ParseError(ValueError):
    """A perf input file is missing or malformed."""


LOSS_COUNTERS = (
    "ktot_gap",
    "ring_drops",
    "overflow_identities",
    "predrop_cfg_fail",
    "predrop_fret_fail",
    "predrop_arg_null",
    "predrop_chase_fail",
    "predrop_name_fail",
    "predrop_destroy_skip",
    "predrop_spare_6",
    "predrop_spare_7",
)

WORKLOAD_REPORT_SCHEMA = "kryprobe.workload-report.v2"

_U64_MAX = 2 ** 64 - 1


def _u64_digit(value, path: Path, what: str) -> int:
    """Strict u64 digit-string (§5.4 integer convention).

    The workload wire emits digit strings (never bare ints —
    serde); bools, floats, negatives, empty/non-digit strings,
    and over-u64 magnitudes refuse (mistyped evidence, never a
    coerced count). ASCII digits only (no unicode-digit trap).
    """
    if isinstance(value, bool) or not isinstance(value, str) \
            or not value:
        raise ParseError(f"{path}: bad {what} {value!r}")
    for char in value:
        if char not in "0123456789":
            raise ParseError(f"{path}: bad {what} {value!r}")
    parsed = int(value)
    if parsed > _U64_MAX:
        raise ParseError(f"{path}: bad {what} {value!r} (over u64)")
    return parsed


def _wire_str(doc: dict, path: Path, *keys: str):
    """Nested required wire string (missing/mistyped refuses)."""
    node = doc
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            raise ParseError(
                f"{path}: workload report lacks {'.'.join(keys)}")
        node = node[key]
    if not isinstance(node, str):
        raise ParseError(
            f"{path}: workload {'.'.join(keys)}={node!r} not str")
    return node


def _wire_bool(doc: dict, path: Path, *keys: str) -> bool:
    """Nested required wire bool (bools only — 0/1 never pass)."""
    node = doc
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            raise ParseError(
                f"{path}: workload report lacks {'.'.join(keys)}")
        node = node[key]
    if not isinstance(node, bool):
        raise ParseError(
            f"{path}: workload {'.'.join(keys)}={node!r} not bool")
    return node


def parse_workload_report(path: Path) -> dict:
    """Parse one workload-report-v2 ``workload-json`` document (M legs).

    Strict shape parse (required keys + wire types); campaign-value
    pins (profile, scope, ledger disposition, coverage, metadata)
    live in ``m1validity.check_m_report``, not here. Every failure
    raises :class:`ParseError` (loud, never a partial parse).
    """
    doc = _read_json(path)
    if not isinstance(doc, dict):
        raise ParseError(f"{path} is not a workload report")
    if doc.get("schema") != WORKLOAD_REPORT_SCHEMA:
        raise ParseError(
            f"{path}: schema {doc.get('schema')!r} is not "
            f"{WORKLOAD_REPORT_SCHEMA}")
    for key in ("session", "interval", "profile", "boundary",
                "dictionary", "contexts", "ledger", "partition",
                "selectors", "scope", "metadata", "coverage"):
        if key not in doc:
            raise ParseError(f"{path}: workload report lacks {key!r}")
    contexts = doc["contexts"]
    if not isinstance(contexts, list):
        raise ParseError(f"{path}: workload contexts not a list")
    rows_sum = 0
    for idx, row in enumerate(contexts):
        if not isinstance(row, dict):
            raise ParseError(
                f"{path}: workload contexts[{idx}] not an object")
        if "calls" not in row:
            raise ParseError(
                f"{path}: workload contexts[{idx}] lacks calls")
        rows_sum += _u64_digit(row["calls"], path,
                               f"contexts[{idx}].calls")
    ledger = doc["ledger"]
    if not isinstance(ledger, dict):
        raise ParseError(f"{path}: workload ledger not an object")
    partition = doc["partition"]
    if not isinstance(partition, dict):
        raise ParseError(f"{path}: workload partition not an object")
    metadata = doc["metadata"]
    if not isinstance(metadata, dict):
        raise ParseError(f"{path}: workload metadata not an object")
    coverage = doc["coverage"]
    if not isinstance(coverage, dict):
        raise ParseError(f"{path}: workload coverage not an object")
    reason = metadata.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ParseError(
            f"{path}: workload metadata.reason={reason!r} not str")
    return {
        "profile": _wire_str(doc, path, "profile"),
        "boundary": _wire_str(doc, path, "boundary"),
        "interval_consistency": _wire_str(doc, path, "interval",
                                          "consistency"),
        "ledger": {
            "system_total": _u64_digit(ledger.get("system_total"),
                                       path, "ledger.system_total"),
            "per_context_sum": _u64_digit(
                ledger.get("per_context_sum"), path,
                "ledger.per_context_sum"),
            "unknown": _u64_digit(ledger.get("unknown"), path,
                                   "ledger.unknown"),
            "consistency": _wire_str(doc, path, "ledger",
                                      "consistency"),
            "gap_unreconciled": _wire_bool(doc, path, "ledger",
                                            "gap_unreconciled"),
            "system_saturated": _wire_bool(doc, path, "ledger",
                                            "system_saturated"),
            "per_context_saturated": _wire_bool(
                doc, path, "ledger", "per_context_saturated"),
            "refused_inserts": _u64_digit(
                ledger.get("refused_inserts"), path,
                "ledger.refused_inserts"),
        },
        "partition": {
            "matched": _u64_digit(partition.get("matched"), path,
                                   "partition.matched"),
            "nonmatched": _u64_digit(partition.get("nonmatched"),
                                      path, "partition.nonmatched"),
            "unknown_match": _u64_digit(
                partition.get("unknown_match"), path,
                "partition.unknown_match"),
        },
        "n_rows": len(contexts),
        "rows_calls_sum": rows_sum,
        "selectors_kind": _wire_str(doc, path, "selectors", "kind"),
        "capture_scope": _wire_str(doc, path, "scope",
                                    "capture_scope"),
        "report_scope": _wire_str(doc, path, "scope",
                                   "report_scope"),
        "group_by": _wire_str(doc, path, "scope", "group_by"),
        "metadata": {"status": _wire_str(doc, path, "metadata",
                                         "status"),
                     "reason": reason},
        "coverage": {
            "capture": _wire_str(doc, path, "coverage", "capture"),
            "attribution": _wire_str(doc, path, "coverage",
                                      "attribution"),
            "metadata": _wire_str(doc, path, "coverage",
                                   "metadata"),
            "correlation": _wire_str(doc, path, "coverage",
                                      "correlation"),
        },
    }


def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text())
    except OSError as err:
        raise ParseError(f"cannot read {path}: {err}") from err
    except json.JSONDecodeError as err:
        raise ParseError(f"bad JSON in {path}: {err}") from err


def parse_api_returns(path: Path) -> dict:
    """Parse one api-returns ``report --system`` JSON document."""
    doc = _read_json(path)
    try:
        observations = doc["observations"]
        coverage = doc["coverage"]
    except (KeyError, TypeError) as err:
        raise ParseError(f"{path} is not an api-returns report: {err}") from err
    agg: dict = {}
    alloc_rows: list = []
    totals: dict = {}
    who: list = []
    lat_nonzero = False
    for obs in observations:
        payload = obs.get("backend_payload", {})
        row = payload.get("row")
        if row == "agg":
            counts = payload.get("counts", {})
            entry = {"calls": counts.get("calls"), "ok": counts.get("ok"),
                     "errors": counts.get("errors"),
                     "queued": counts.get("queued"),
                     "bytes": payload.get("bytes"),
                     "algorithm": payload.get("algorithm")}
            if payload.get("family") == "any" and payload.get("op") == "alloc":
                alloc_rows.append(entry)
            else:
                key = (payload.get("family"), payload.get("op"),
                       payload.get("driver"))
                if key in agg:
                    raise ParseError(
                        f"{path}: duplicate agg row {key}")
                agg[key] = entry
            for bucket in payload.get("lat") or []:
                if bucket:
                    lat_nonzero = True
        elif row == "totals":
            totals = dict(payload.get("counts", {}))
        elif row == "who":
            who.append({"comm": payload.get("comm"),
                        "tgid": payload.get("tgid"),
                        "tid": payload.get("tid"),
                        "calls": payload.get("calls"),
                        "stack": payload.get("stack")})
    loss: dict = {}
    for dim in ("aggregate_counts", "detailed_events"):
        for counter in coverage.get(dim, {}).get("counters", []):
            name = counter.get("name")
            if name in LOSS_COUNTERS:
                try:
                    loss[name] = int(counter.get("value"))
                except (TypeError, ValueError) as err:
                    raise ParseError(
                        f"{path}: bad loss counter {name}: {err}") from err
    missing = [name for name in LOSS_COUNTERS if name not in loss]
    if missing:
        raise ParseError(f"{path}: missing loss counters {missing}")
    return {"agg": agg, "alloc_rows": alloc_rows, "totals": totals,
            "who": who, "loss": loss, "verdict": doc.get("verdict"),
            "lat_nonzero": lat_nonzero}


def parse_lifecycle(path: Path) -> dict:
    """Parse one request-lifecycle jsonl session file."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as err:
        raise ParseError(f"cannot read {path}: {err}") from err
    kinds: dict = {}
    observations = 0
    terminals: dict = {}
    receipt = None
    coverage_row = None
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as err:
            raise ParseError(
                f"{path}:{lineno}: bad jsonl: {err}") from err
        kind = record.get("kind")
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind == "observation":
            observations += 1
            terminal = record.get("record", {}).get("terminal")
            terminals[terminal] = terminals.get(terminal, 0) + 1
        elif kind == "session_receipt":
            receipt = record
        elif kind == "coverage":
            coverage_row = record
    if receipt is None:
        raise ParseError(f"{path}: no session_receipt row")
    for key in ("verdict", "truncated", "admitted", "emitted",
                "unfinished", "loss"):
        if key not in receipt:
            raise ParseError(f"{path}: receipt lacks {key}")
    return {"kinds": kinds, "observations": observations,
            "terminals": terminals, "receipt": receipt,
            "coverage": coverage_row}


def parse_ledger_csv(path: Path) -> list:
    """Parse a driver ledger CSV into (seq, phase, op, dt_ns) rows."""
    try:
        text = Path(path).read_text().splitlines()
    except OSError as err:
        raise ParseError(f"cannot read {path}: {err}") from err
    reader = csv.reader(text)
    try:
        header = next(reader)
    except StopIteration as err:
        raise ParseError(f"{path}: empty ledger") from err
    if header != ["seq", "phase", "op", "dt_ns"]:
        raise ParseError(f"{path}: bad ledger header {header}")
    rows = []
    for lineno, parts in enumerate(reader, 2):
        if len(parts) != 4:
            raise ParseError(f"{path}:{lineno}: bad row {parts}")
        try:
            rows.append((int(parts[0]), parts[1], parts[2], int(parts[3])))
        except ValueError as err:
            raise ParseError(
                f"{path}:{lineno}: bad row {parts}: {err}") from err
    return rows


def parse_sampler(path: Path) -> dict:
    """Parse a guest rss-sampler log (header + 1 Hz samples)."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as err:
        raise ParseError(f"cannot read {path}: {err}") from err
    clk_tck = None
    samples = []
    for line in lines:
        if line.startswith("clk_tck="):
            try:
                clk_tck = int(line.split("=", 1)[1])
            except ValueError as err:
                raise ParseError(f"{path}: bad clk_tck: {err}") from err
            continue
        parts = dict(bit.split("=", 1) for bit in line.split()
                     if "=" in bit)
        try:
            samples.append((int(parts["t"]), int(parts["rss_kb"]),
                            int(parts["utime"]), int(parts["stime"])))
        except (KeyError, ValueError) as err:
            raise ParseError(f"{path}: bad sample {line!r}: {err}") from err
    if clk_tck is None or not samples:
        raise ParseError(f"{path}: no usable sampler data")
    rss_max = max(sample[1] for sample in samples)
    cpu_ticks = ((samples[-1][2] - samples[0][2])
                 + (samples[-1][3] - samples[0][3]))
    return {"rss_max_kb": rss_max, "cpu_s": cpu_ticks / clk_tck,
            "samples": len(samples)}


TELEMETRY_PREFIX = "kryprobe: telemetry "
TELEMETRY_VERSION = 1


def parse_telemetry(path: Path) -> dict:
    """Fold R1 machine-readable telemetry from a capture stderr log.

    Ticks fold to the session max drain lag (``lagmax_us``); the
    last stop-span/occupancy object wins. Malformed lines, unknown
    versions, and present-but-invalid lag values (floats included —
    never rounded) are counted (never fatal — telemetry is
    best-effort observability, not validity input). A missing file
    raises :class:`ParseError` (module discipline).
    """
    try:
        text = Path(path).read_text()
    except OSError as err:
        raise ParseError(f"cannot read {path}: {err}") from err
    lagmax = None
    stop = None
    occupancy = None
    lines = 0
    malformed = 0
    for raw in text.splitlines():
        if not raw.startswith(TELEMETRY_PREFIX):
            continue
        lines += 1
        try:
            obj = json.loads(raw[len(TELEMETRY_PREFIX):])
        except ValueError:
            malformed += 1
            continue
        if not isinstance(obj, dict) or obj.get("v") != TELEMETRY_VERSION:
            malformed += 1
            continue
        lag = obj.get("lagmax_us")
        if isinstance(lag, int) and not isinstance(lag, bool):
            lagmax = lag if lagmax is None else max(lagmax, lag)
        elif lag is not None:
            # Present non-null lag of the wrong type (float, str,
            # bool): malformed, never silently rounded or ignored.
            # Intentional null / absent lag stays uncounted; the
            # line's stop/occupancy objects still fold below.
            malformed += 1
        if isinstance(obj.get("stop"), dict):
            stop = obj["stop"]
        if isinstance(obj.get("occupancy"), dict):
            occupancy = obj["occupancy"]
    return {"lagmax_us": lagmax, "stop": stop, "occupancy": occupancy,
            "lines": lines, "malformed": malformed}
