#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict guest-console parsing for the P10 demo campaign (attempt 4).

The guest speaks to the host only through serial-console marker
lines. Single-line markers look like ``DEMO:<channel> <json>``;
the product report rides a multi-line passthrough between
``DEMO:KRYPROBE-BEGIN`` and ``DEMO:KRYPROBE-END``, and D08 soak
windows ride numbered bounded blocks between
``DEMO:KRYPROBE-WINDOW-BEGIN`` and ``DEMO:KRYPROBE-WINDOW-END``.
Kernel noise is ignored but counted. Anything else refuses loudly:

- unknown channels, malformed prefixes, malformed JSON;
- unterminated or nested passthrough blocks;
- denylisted secret-ish JSON keys (``key``, ``iv``, ``tag``,
  ``payload``, ``plaintext``, ``ciphertext``, ``aad``, ``kaddr``)
  anywhere in a DEMO line — the guest tools must never emit
  secret material, and the parser is the second gate. The
  KRYPROBE passthrough and the numbered window blocks are
  exempt: their bytes come from the hash-pinned, P9-accepted
  product renderer (fixed v0 schema), never from guest tools,
  so a product field name cannot fail the guest's hygiene gate.

:func:`check_sequence` additionally requires ledger rows to be
gapless from 0: a gap is lost evidence, never a pass.
"""

from __future__ import annotations

import json

CHANNELS = frozenset(
    {
        "LEDGER",
        "REGISTRY",
        "DMAP",
        "IO",
        "PROBE",
        "MARK",
        "CPU",
        "HANDLE",
        "VIRTIO",
        "SOAK",
    }
)

DENIED_KEYS = frozenset(
    {
        "key",
        "iv",
        "tag",
        "payload",
        "plaintext",
        "ciphertext",
        "aad",
        "kaddr",
    }
)

BEGIN = "DEMO:KRYPROBE-BEGIN"
END = "DEMO:KRYPROBE-END"

# Numbered per-window product reports (D08 loss accounting): every
# soak window's report reaches the console in its own bounded block
# so the oracle validates each window instead of asserting
# unmeasured zero loss.
WINDOW_BEGIN = "DEMO:KRYPROBE-WINDOW-BEGIN"
WINDOW_END = "DEMO:KRYPROBE-WINDOW-END"
WINDOW_MAX_BYTES = 1_000_000
WINDOW_MAX_ID = 255


class ConsoleError(ValueError):
    """Console evidence refused: unparseable, gapped, or unsafe."""


def _scan_denied(obj) -> None:
    """Refuse denylisted secret-ish keys anywhere in the object."""
    if isinstance(obj, dict):
        for name, value in obj.items():
            if name in DENIED_KEYS:
                raise ConsoleError(f"denied secret-ish key {name!r} in console marker")
            _scan_denied(value)
    elif isinstance(obj, list):
        for value in obj:
            _scan_denied(value)


def _window_id(header: str, lineno: int, marker: str) -> int:
    """Strict window number from a WINDOW-BEGIN/END header payload."""
    try:
        obj = json.loads(header)
    except json.JSONDecodeError as err:
        raise ConsoleError(
            f"line {lineno}: {marker} header is not JSON: {err}"
        ) from err
    if not isinstance(obj, dict):
        raise ConsoleError(
            f"line {lineno}: {marker} header must be an object")
    window = obj.get("window")
    if type(window) is not int or not 0 <= window <= WINDOW_MAX_ID:
        raise ConsoleError(
            f"line {lineno}: {marker} window {window!r} out of range")
    return window


def parse_console(text: str) -> dict:
    """Parse console text into per-channel rows (strict, fail-closed).

    Returns a dict with one list per known channel, ``KRYPROBE``
    (the reassembled product-report object or ``None``),
    ``KRYPROBE_WINDOWS`` (window number -> ``{"report", "lines"}``
    for numbered per-window blocks), and ``noise_lines``
    (non-marker lines ignored with provenance).
    """
    parsed: dict = {channel: [] for channel in sorted(CHANNELS)}
    parsed["KRYPROBE"] = None
    parsed["KRYPROBE_WINDOWS"] = {}
    parsed["noise_lines"] = 0
    passthrough: list[str] | None = None
    window_open: int | None = None
    window_lines: list[str] = []
    window_bytes = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if passthrough is not None:
            if line == BEGIN:
                raise ConsoleError(f"line {lineno}: nested {BEGIN}")
            if line.startswith(WINDOW_BEGIN) or line.startswith(WINDOW_END):
                raise ConsoleError(
                    f"line {lineno}: window marker inside {BEGIN} block")
            if line == END:
                body = "\n".join(passthrough)
                try:
                    report = json.loads(body)
                except json.JSONDecodeError as err:
                    raise ConsoleError(
                        f"line {lineno}: KRYPROBE passthrough is not JSON: {err}"
                    ) from err
                if parsed["KRYPROBE"] is not None:
                    raise ConsoleError(f"line {lineno}: duplicate {BEGIN} block")
                # No denylist scan here: product-owned bytes (see module
                # docstring); DEMO channels below are still scanned.
                parsed["KRYPROBE"] = report
                passthrough = None
                continue
            passthrough.append(raw.rstrip("\n"))
            continue
        if window_open is not None:
            if line == BEGIN:
                raise ConsoleError(
                    f"line {lineno}: {BEGIN} inside window block")
            if line.startswith(WINDOW_BEGIN):
                raise ConsoleError(
                    f"line {lineno}: nested {WINDOW_BEGIN}")
            if line.startswith(WINDOW_END):
                rest = line[len(WINDOW_END):]
                if not rest.startswith(" "):
                    raise ConsoleError(
                        f"line {lineno}: {WINDOW_END} without a header")
                closing = _window_id(rest[1:], lineno, WINDOW_END)
                if closing != window_open:
                    raise ConsoleError(
                        f"line {lineno}: {WINDOW_END} window {closing} "
                        f"does not match open window {window_open}")
                body = "\n".join(window_lines)
                try:
                    report = json.loads(body)
                except json.JSONDecodeError as err:
                    raise ConsoleError(
                        f"line {lineno}: window {window_open} body "
                        f"is not JSON: {err}"
                    ) from err
                # No denylist scan: product-owned bytes, like the
                # legacy passthrough.
                parsed["KRYPROBE_WINDOWS"][window_open] = {
                    "report": report,
                    "lines": sum(1 for entry in window_lines if entry),
                }
                window_open = None
                window_lines = []
                window_bytes = 0
                continue
            window_bytes += len(raw) + 1
            if window_bytes > WINDOW_MAX_BYTES:
                raise ConsoleError(
                    f"line {lineno}: window {window_open} block exceeds "
                    f"{WINDOW_MAX_BYTES} bytes")
            window_lines.append(raw.rstrip("\n"))
            continue
        if line == BEGIN:
            passthrough = []
            continue
        if line.startswith(WINDOW_BEGIN):
            rest = line[len(WINDOW_BEGIN):]
            if not rest.startswith(" "):
                raise ConsoleError(
                    f"line {lineno}: {WINDOW_BEGIN} without a header")
            window = _window_id(rest[1:], lineno, WINDOW_BEGIN)
            if window in parsed["KRYPROBE_WINDOWS"]:
                raise ConsoleError(
                    f"line {lineno}: duplicate window {window} block")
            window_open = window
            window_lines = []
            window_bytes = 0
            continue
        if line.startswith(WINDOW_END):
            raise ConsoleError(f"line {lineno}: {WINDOW_END} without {WINDOW_BEGIN}")
        if line == END:
            raise ConsoleError(f"line {lineno}: {END} without {BEGIN}")
        if not line.startswith("DEMO:"):
            if line.startswith("DEMO"):
                raise ConsoleError(f"line {lineno}: malformed marker prefix")
            parsed["noise_lines"] += 1
            continue
        rest = line[len("DEMO:"):]
        channel, sep, body = rest.partition(" ")
        if not sep or channel not in CHANNELS:
            raise ConsoleError(f"line {lineno}: unknown console channel {channel!r}")
        try:
            row = json.loads(body)
        except json.JSONDecodeError as err:
            raise ConsoleError(
                f"line {lineno}: channel {channel} body is not JSON: {err}"
            ) from err
        if not isinstance(row, dict):
            raise ConsoleError(f"line {lineno}: channel {channel} row must be an object")
        _scan_denied(row)
        parsed[channel].append(row)
    if passthrough is not None:
        raise ConsoleError(f"unterminated {BEGIN} block")
    if window_open is not None:
        raise ConsoleError(f"unterminated {WINDOW_BEGIN} window {window_open}")
    return parsed


def check_sequence(rows: list[dict]) -> dict:
    """Require gapless ``seq`` 0..N-1; return ``{"count": N}``."""
    if not rows:
        raise ConsoleError("ledger has no rows (want at least one)")
    seen: set[int] = set()
    for row in rows:
        seq = row.get("seq")
        if type(seq) is not int or seq < 0:
            raise ConsoleError(f"ledger row without a natural seq: {row!r}")
        if seq in seen:
            raise ConsoleError(f"duplicate ledger seq {seq}")
        seen.add(seq)
    if seen != set(range(len(rows))):
        missing = sorted(set(range(len(rows))) - seen)
        raise ConsoleError(f"ledger sequence gap (missing seqs {missing!r})")
    return {"count": len(rows)}


def marks_ordered(marks: list[dict], want: list[str]) -> bool:
    """True iff every wanted mark appears in order with strict ts_mono."""
    cursor = -1
    last_ts: float | None = None
    for name in want:
        found = None
        for index in range(cursor + 1, len(marks)):
            if marks[index].get("name") == name:
                found = index
                break
        if found is None:
            return False
        ts = marks[found].get("ts_mono")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            return False
        if last_ts is not None and not ts > last_ts:
            return False
        last_ts = ts
        cursor = found
    return True
