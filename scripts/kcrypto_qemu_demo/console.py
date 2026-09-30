#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict guest-console parsing for the P10 demo campaign (attempt 4).

The guest speaks to the host only through serial-console marker
lines. Single-line markers look like ``DEMO:<channel> <json>``;
the product report rides a multi-line passthrough between
``DEMO:KRYPROBE-BEGIN`` and ``DEMO:KRYPROBE-END``. Kernel noise
is ignored but counted. Anything else refuses loudly:

- unknown channels, malformed prefixes, malformed JSON;
- unterminated or nested passthrough blocks;
- denylisted secret-ish JSON keys (``key``, ``iv``, ``tag``,
  ``payload``, ``plaintext``, ``ciphertext``, ``aad``, ``kaddr``)
  anywhere in a DEMO line — the guest tools must never emit
  secret material, and the parser is the second gate. The
  KRYPROBE passthrough is exempt: its bytes come from the
  hash-pinned, P9-accepted product renderer (fixed v0 schema),
  never from guest tools, so a product field name cannot fail
  the guest's hygiene gate.

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


def parse_console(text: str) -> dict:
    """Parse console text into per-channel rows (strict, fail-closed).

    Returns a dict with one list per known channel, ``KRYPROBE``
    (the reassembled product-report object or ``None``), and
    ``noise_lines`` (non-marker lines ignored with provenance).
    """
    parsed: dict = {channel: [] for channel in sorted(CHANNELS)}
    parsed["KRYPROBE"] = None
    parsed["noise_lines"] = 0
    passthrough: list[str] | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if passthrough is not None:
            if line == BEGIN:
                raise ConsoleError(f"line {lineno}: nested {BEGIN}")
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
        if line == BEGIN:
            passthrough = []
            continue
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
