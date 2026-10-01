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
    last stop-span/occupancy object wins. Malformed lines and
    unknown versions are counted (never fatal — telemetry is
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
        if isinstance(obj.get("stop"), dict):
            stop = obj["stop"]
        if isinstance(obj.get("occupancy"), dict):
            occupancy = obj["occupancy"]
    return {"lagmax_us": lagmax, "stop": stop, "occupancy": occupancy,
            "lines": lines, "malformed": malformed}
