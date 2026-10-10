# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict versioned loader for the M1 early-gate perf manifest.

Reads ``tests/kcrypto_perf/cells-m1.json`` (schema
``kryprobe-perf-campaign-m1/v1``) and refuses anything else. Same
freeze binding as the frozen loader (``_manifest_sha256`` over the
exact input bytes). M1 sets name per-side modes + observer roles and
their own pair/attempt counts (ADR-0016: 10 valid / 12 attempted for
judged sets; controls may use fewer pairs but never fewer than the
frozen 5/8 floor... controls use exactly 5/8 here).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA = "kryprobe-perf-campaign-m1/v1"

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
    "workloads",
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
    "kernel",
    "workload",
    "budgeted",
    "mode_a",
    "mode_b",
    "obs_a",
    "obs_b",
    "pairs",
    "max_attempted",
})

REQUIRED_WORKLOAD_KEYS = frozenset({
    "driver_threads",
    "driver_flags",
    "expected_rows",
})

KERNELS = frozenset({"6.12.111", "7.0.14", "7.2.6"})

WORKLOADS = frozenset({"single", "n_cgroup", "churn_below", "churn_full"})

MODES = frozenset({"disabled", "aggregation"})

# Task05 Stage 4 (freeze G1): M joins the observer roles (K bytes +
# bounded metadata file + helper sibling, workload-json legs). M
# pairs with aggregation only (the mode/obs mismatch rule below
# enforces it: disabled ⟺ D).
OBS = frozenset({"R", "C", "M", "D"})


class InputError(ValueError):
    """Strict loader refusal: the manifest is not the M1 v1 shape."""


def manifest_sha256(path: Path) -> str:
    """sha256 of the exact manifest bytes (freeze binding for receipts)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_manifest(path: Path) -> dict:
    """Load and strictly validate the M1 perf manifest."""
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
    if not isinstance(manifest["workloads"], dict) or \
            not manifest["workloads"]:
        raise InputError("manifest workloads must be a non-empty object")
    for name, workload in manifest["workloads"].items():
        if name not in WORKLOADS:
            raise InputError(f"unknown workload {name!r}")
        missing = REQUIRED_WORKLOAD_KEYS - workload.keys()
        if missing:
            raise InputError(f"workload {name} lacks {sorted(missing)}")
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
        if entry["workload"] not in WORKLOADS:
            raise InputError(f"unknown set workload {entry['workload']!r}")
        for side in ("mode_a", "mode_b"):
            if entry[side] not in MODES:
                raise InputError(f"unknown set {side} {entry[side]!r}")
        for side in ("obs_a", "obs_b"):
            if entry[side] not in OBS:
                raise InputError(f"unknown set {side} {entry[side]!r}")
        if (entry["mode_a"] == "disabled") != (entry["obs_a"] == "D"):
            raise InputError(f"set {entry['id']}: side A mode/obs mismatch")
        if (entry["mode_b"] == "disabled") != (entry["obs_b"] == "D"):
            raise InputError(f"set {entry['id']}: side B mode/obs mismatch")
        if entry["obs_b"] == "D":
            # F-05: the scenario quiet leg always runs the side-B
            # observer binary; a DISABLED side B has no binary (loud
            # boot abort). Disabled sides live on side A by design.
            raise InputError(f"set {entry['id']}: side B must be an "
                             f"observer (R/C/M), not D")
        if type(entry["pairs"]) is not int or entry["pairs"] < 5:
            raise InputError(f"set {entry['id']}: pairs must be int >= 5")
        if type(entry["max_attempted"]) is not int or \
                entry["max_attempted"] < entry["pairs"]:
            raise InputError(f"set {entry['id']}: max_attempted < pairs")
    if not isinstance(manifest["diagnostics"], list):
        raise InputError("manifest diagnostics must be a list")
    for entry in manifest["diagnostics"]:
        if not isinstance(entry, dict) or "id" not in entry \
                or "kind" not in entry or "kernel" not in entry:
            raise InputError("manifest diagnostic lacks id/kind/kernel")
        if entry["kernel"] not in KERNELS:
            raise InputError(
                f"unknown diagnostic kernel {entry['kernel']!r}")
        if entry["kind"] == "m1-612-ctx":
            for key in ("class", "workload", "size"):
                if key not in entry:
                    raise InputError(
                        f"diagnostic {entry['id']} lacks {key!r}")
            if entry["class"] not in manifest["classes"]:
                raise InputError(
                    f"unknown diagnostic class {entry['class']!r}")
            if entry["workload"] not in WORKLOADS:
                raise InputError(
                    f"unknown diagnostic workload {entry['workload']!r}")
    manifest["_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return manifest
