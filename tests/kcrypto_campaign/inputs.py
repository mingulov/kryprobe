#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict versioned loader for the frozen P2 pressure manifest.

P2/K05 host half: reads ``pressure.json`` (schema
``kryprobe-pressure-campaign/v1``) and refuses anything else —
unknown schema/version (type-strict: ``True`` is not ``1``), missing
required keys, duplicate cell or portion IDs, unknown statuses,
non-mapping cells, or empty/non-mapping stimulus/oracle/bounds/
global tables (P2r/C7). The manifest is immutable
once frozen: :func:`load_inputs` returns the manifest sha256 so
receipts can bind the exact bytes they ran against (P8 extension:
full preflight hash/limit binding in ``inputs.py`` per the test
plan; this module keeps the strict core small).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA = "kryprobe-pressure-campaign/v1"

REQUIRED_TOP_KEYS = frozenset(
    {
        "$schema",
        "campaign",
        "manifest_version",
        "frozen_utc",
        "freeze_rule",
        "global",
        "mode_decision",
        "cells",
    }
)

REQUIRED_CELL_KEYS = frozenset({"id", "title", "status", "stimulus", "oracle", "bounds", "portions"})

REQUIRED_PORTION_KEYS = frozenset({"id", "status"})

STATUSES = frozenset({"P2", "NOT_RUN"})


class InputError(ValueError):
    """Strict loader refusal: the manifest is not the frozen v1 shape."""


def manifest_sha256(path: Path) -> str:
    """sha256 of the exact manifest bytes (freeze binding for receipts)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_inputs(path: Path) -> dict:
    """Load and strictly validate the frozen campaign manifest.

    Returns the parsed manifest dict with an added ``_manifest_sha256``
    key binding the exact input bytes. Raises :class:`InputError` on
    any deviation (never a partial/``None`` manifest).
    """
    raw = Path(path).read_bytes()
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as err:
        raise InputError(f"manifest is not valid JSON: {err}") from err
    if not isinstance(manifest, dict):
        raise InputError("manifest top level must be an object")
    missing = REQUIRED_TOP_KEYS - manifest.keys()
    if missing:
        raise InputError(f"manifest missing required keys: {sorted(missing)}")
    if manifest["$schema"] != SCHEMA:
        raise InputError(
            f"unknown manifest schema {manifest['$schema']!r} (want {SCHEMA!r})"
        )
    # P2r/C7: type-strict — True == 1 in Python, so == alone would
    # accept a bool version.
    if type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 1:
        raise InputError(
            f"unknown manifest_version {manifest['manifest_version']!r} (want int 1)"
        )
    # P2r/C7: the shared limits table must be a genuine nonempty
    # mapping, not an empty/non-mapping placeholder.
    if not isinstance(manifest["global"], dict) or not manifest["global"]:
        raise InputError(
            f"manifest 'global' must be a nonempty mapping, got {manifest['global']!r}"
        )
    cells = manifest["cells"]
    if not isinstance(cells, list) or not cells:
        raise InputError("manifest 'cells' must be a non-empty list")
    seen: set[str] = set()
    for cell in cells:
        if not isinstance(cell, dict):
            raise InputError("every cell must be an object")
        missing = REQUIRED_CELL_KEYS - cell.keys()
        if missing:
            raise InputError(
                f"cell {cell.get('id', '?')!r} missing required keys: {sorted(missing)}"
            )
        cell_id = cell["id"]
        if cell_id in seen:
            raise InputError(f"duplicate cell id {cell_id!r}")
        seen.add(cell_id)
        if cell["status"] not in STATUSES:
            raise InputError(f"cell {cell_id!r} has unknown status {cell['status']!r}")
        # P2r/C7: stimulus/oracle/bounds must be nonempty mappings —
        # an empty dict would silently unbind the frozen limits.
        for key in ("stimulus", "oracle", "bounds"):
            if not isinstance(cell[key], dict) or not cell[key]:
                raise InputError(
                    f"cell {cell_id!r} {key!r} must be a nonempty mapping, "
                    f"got {cell[key]!r}"
                )
        portions = cell["portions"]
        if not isinstance(portions, list) or not portions:
            raise InputError(f"cell {cell_id!r} 'portions' must be a non-empty list")
        seen_portions: set[str] = set()
        for portion in portions:
            if not isinstance(portion, dict):
                raise InputError(f"cell {cell_id!r} has a non-object portion")
            missing = REQUIRED_PORTION_KEYS - portion.keys()
            if missing:
                raise InputError(
                    f"cell {cell_id!r} portion missing required keys: {sorted(missing)}"
                )
            portion_id = portion["id"]
            if portion_id in seen_portions:
                raise InputError(
                    f"cell {cell_id!r} has a duplicate portion id {portion_id!r}"
                )
            seen_portions.add(portion_id)
            if portion["status"] not in STATUSES:
                raise InputError(
                    f"cell {cell_id!r} portion {portion.get('id', '?')!r} "
                    f"has unknown status {portion['status']!r}"
                )
    manifest["_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return manifest


def p2_cells(manifest: dict) -> list[dict]:
    """Cells (or portions) with P2 status — the runnable P2 set."""
    runnable = []
    for cell in manifest["cells"]:
        portions = [p for p in cell["portions"] if p["status"] == "P2"]
        if cell["status"] == "P2" and portions:
            runnable.append({"id": cell["id"], "portions": [p["id"] for p in portions]})
    return runnable
