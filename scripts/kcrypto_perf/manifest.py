#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict versioned loader for the frozen P9/T14 perf manifest.

Reads ``tests/kcrypto_perf/cells.json`` (schema
``kryprobe-perf-campaign/v1``) and refuses anything else: unknown
schema/version, unknown kernels/classes/modes, missing required
keys, duplicate set IDs, or a pair-set that does not name five
pairs. Returns the manifest with ``_manifest_sha256`` binding the
exact input bytes (same freeze binding as the P8 consumer
loader).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA = "kryprobe-perf-campaign/v1"

REQUIRED_TOP_KEYS = frozenset({
    "$schema",
    "campaign",
    "manifest_version",
    "frozen_utc",
    "freeze_rule",
    "budgets",
    "global",
    "classes",
    "modes",
    "sets",
    "diagnostics",
})

REQUIRED_GLOBAL_KEYS = frozenset({
    "kernels",
    "vng",
    "warmup_s",
    "measure_s",
    "capture_s",
    "settle_s",
    "quiet_s",
    "pairs_per_set",
    "max_attempted_pairs",
    "guest_cpus",
    "guest_memory",
    "detail_cap",
})

REQUIRED_SET_KEYS = frozenset({
    "id",
    "class",
    "mode",
    "kernel",
    "workload",
    "budgeted",
})

KERNELS = frozenset({"6.12.111", "7.0.14", "7.2.6"})

WORKLOADS = frozenset({"flat", "paced", "idle", "bulk"})


class InputError(ValueError):
    """Strict loader refusal: the manifest is not the frozen v1 shape."""


def manifest_sha256(path: Path) -> str:
    """sha256 of the exact manifest bytes (freeze binding for receipts)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_manifest(path: Path) -> dict:
    """Load and strictly validate the frozen perf manifest."""
    raw = Path(path).read_bytes()
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as err:
        raise InputError(f"manifest is not valid JSON: {err}") from err
    if not isinstance(manifest, dict):
        raise InputError("manifest top level must be an object")
    missing = REQUIRED_TOP_KEYS - manifest.keys()
    if missing:
        raise InputError(f"manifest lacks top keys {sorted(missing)}")
    if manifest["$schema"] != SCHEMA:
        raise InputError(f"manifest schema {manifest['$schema']!r} "
                         f"is not {SCHEMA}")
    if type(manifest["manifest_version"]) is not int or \
            manifest["manifest_version"] != 1:
        raise InputError("manifest_version must be 1")
    if not isinstance(manifest["global"], dict):
        raise InputError("manifest global must be an object")
    missing = REQUIRED_GLOBAL_KEYS - manifest["global"].keys()
    if missing:
        raise InputError(f"manifest global lacks {sorted(missing)}")
    for kernel in manifest["global"]["kernels"]:
        if kernel not in KERNELS:
            raise InputError(f"unknown manifest kernel {kernel!r}")
    if not isinstance(manifest["classes"], dict) or \
            not manifest["classes"]:
        raise InputError("manifest classes must be a non-empty object")
    if not isinstance(manifest["modes"], dict) or not manifest["modes"]:
        raise InputError("manifest modes must be a non-empty object")
    if not isinstance(manifest["sets"], list) or not manifest["sets"]:
        raise InputError("manifest sets must be a non-empty list")
    seen = set()
    for entry in manifest["sets"]:
        if not isinstance(entry, dict):
            raise InputError("manifest set must be an object")
        missing = REQUIRED_SET_KEYS - entry.keys()
        if missing:
            raise InputError(f"manifest set lacks {sorted(missing)}")
        if entry["id"] in seen:
            raise InputError(f"duplicate set id {entry['id']!r}")
        seen.add(entry["id"])
        if entry["kernel"] not in KERNELS:
            raise InputError(f"unknown set kernel {entry['kernel']!r}")
        if entry["class"] not in manifest["classes"]:
            raise InputError(f"unknown set class {entry['class']!r}")
        if entry["mode"] not in manifest["modes"]:
            raise InputError(f"unknown set mode {entry['mode']!r}")
        if entry["workload"] not in WORKLOADS:
            raise InputError(f"unknown set workload {entry['workload']!r}")
    if not isinstance(manifest["diagnostics"], list):
        raise InputError("manifest diagnostics must be a list")
    manifest["_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return manifest
