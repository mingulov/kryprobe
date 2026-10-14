#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared helpers for the Task05 Stage 4 workload labs (freeze G11).

Fixture-ledger format + validation, the flat-shape per-cgroup
reconciliation oracle, owned-resource inventory diffing, and the C7
installed-leg helpers (non-exited sentinel checks, the 1 s owned-reap
grace). Pure-python, side-effect-free import: host tests exercise
every pure function; live guest execution is NOT_RUN on this host.
"""

from __future__ import annotations

import json
from pathlib import Path

LAB_TAG = "kryprobe-m1-05"

LEDGER_SCHEMA = "kryprobe-workload-lab-ledger/v1"

# C7-2: the 1 s owned-reap grace (workload_launch.rs:1149 can exceed
# the attempt deadline; 1 s is accepted as bounded, not proven
# minimal) belongs in every enclosing timeout budget on installed
# legs — callers add this, never bare attempt deadlines.
OWNED_REAP_GRACE_S = 1.0


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_fixture_ledger(ledger: dict) -> list:
    """Validate one fixture self-count ledger (independent oracle
    input). Shape: {"schema": LEDGER_SCHEMA, "workloads": [{name,
    cgroup_id, ops, allocs}]}. Names and cgroup IDs unique;
    cgroup IDs digit strings (kernel cgroupfs inodes); ops a
    positive int; allocs a non-negative int. Returns reasons
    (empty = valid)."""
    reasons = []
    if not isinstance(ledger, dict):
        return ["ledger not an object"]
    if ledger.get("schema") != LEDGER_SCHEMA:
        reasons.append(f"schema {ledger.get('schema')!r} refused")
    workloads = ledger.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        return reasons + ["workloads must be a non-empty list"]
    seen_names: set = set()
    seen_cgroups: set = set()
    for idx, entry in enumerate(workloads):
        where = f"workloads[{idx}]"
        if not isinstance(entry, dict):
            reasons.append(f"{where} not an object")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            reasons.append(f"{where}.name must be a non-empty str")
        elif name in seen_names:
            reasons.append(f"{where}.name {name!r} duplicated")
        else:
            seen_names.add(name)
        cgroup = entry.get("cgroup_id")
        if not isinstance(cgroup, str) or not cgroup or \
                any(char not in "0123456789" for char in cgroup):
            reasons.append(f"{where}.cgroup_id must be a digit str")
        elif cgroup in seen_cgroups:
            reasons.append(f"{where}.cgroup_id {cgroup!r} duplicated")
        else:
            seen_cgroups.add(cgroup)
        ops = entry.get("ops")
        if not _is_int(ops) or ops <= 0:
            reasons.append(f"{where}.ops must be a positive int")
        allocs = entry.get("allocs")
        if not _is_int(allocs) or allocs < 0:
            reasons.append(f"{where}.allocs must be a non-neg int")
    return reasons


def reconcile_cgroup(ops: int, enc: int, dec: int) -> list:
    """Flat-shape per-cgroup oracle (7.x kernels): the BPF
    per-operation per-cgroup counts (enc/dec folded from the
    workload-json contexts by native op) must equal the fixture
    self-counted ops exactly (early-gate equivalence: enc == dec
    == driver ops_total). Userspace counting vs BPF observation
    are independent paths — agreement reconciles them. Returns
    reasons (empty = reconciled). See reconcile_cgroup_nested
    for the 6.12 floor."""
    reasons = []
    if enc != ops:
        reasons.append(f"cgroup enc={enc} != fixture ops={ops}")
    if dec != ops:
        reasons.append(f"cgroup dec={dec} != fixture ops={ops}")
    return reasons


NESTED_SKCIPHER_LAYERS = ("cbc(aes)", "__cbc(aes)")


def reconcile_cgroup_nested(ops: int, enc_layers: dict,
                            dec_layers: dict) -> list:
    """Nested-shape per-cgroup oracle (6.12 floor): the BPF
    per-operation per-cgroup counts show one outer + one
    cryptd-nested inner call per op per direction (2x issued
    in total; the R01-floor-612 seal pins the
    cbc(aes)/__cbc(aes) split at issued/issued per
    direction). Each pinned layer must equal the fixture
    self-counted ops exactly, and the split itself is
    asserted: a missing, extra, or short layer fails.
    Returns reasons (empty = reconciled)."""
    reasons = []
    for direction, layers in (("enc", enc_layers),
                              ("dec", dec_layers)):
        for name in NESTED_SKCIPHER_LAYERS:
            if name not in layers:
                reasons.append(f"cgroup {direction} layer "
                               f"{name} missing")
            elif layers[name] != ops:
                reasons.append(
                    f"cgroup {direction} layer {name}="
                    f"{layers[name]} != fixture ops={ops}")
        for name in sorted(layers):
            if name not in NESTED_SKCIPHER_LAYERS:
                reasons.append(f"cgroup {direction} layer "
                               f"{name} unpinned")
    return reasons


def write_ledger(path: Path, ledger: dict) -> None:
    """Write one fixture ledger (validated first, never partial)."""
    reasons = check_fixture_ledger(ledger)
    if reasons:
        raise ValueError(f"refusing to write ledger: {reasons}")
    Path(path).write_text(json.dumps(ledger, indent=1) + "\n")


def read_ledger(path: Path) -> dict:
    """Read + validate one fixture ledger."""
    ledger = json.loads(Path(path).read_text())
    reasons = check_fixture_ledger(ledger)
    if reasons:
        raise ValueError(f"ledger {path} invalid: {reasons}")
    return ledger


def diff_inventory(before: dict, after: dict,
                   owned_prefix: str = LAB_TAG) -> list:
    """No-unrelated-resources oracle (spec §11.7): every inventory
    dimension added between the pre-setup and post-cleanup
    snapshots must carry the owned prefix; removals of owned
    names are the cleanup itself. Dimensions are {name: [ids]}.
    Returns reasons (empty = no unrelated resource touched)."""
    reasons = []
    for dim in sorted(set(before) | set(after)):
        old = set(before.get(dim) or [])
        new = set(after.get(dim) or [])
        for name in sorted(new - old):
            if owned_prefix not in str(name):
                reasons.append(f"{dim}: unrelated {name!r} added")
        for name in sorted(old - new):
            if owned_prefix not in str(name):
                reasons.append(f"{dim}: unrelated {name!r} removed")
    return reasons


def proc_exited(pid: int) -> bool:
    """C7-3: True when the process has exited — including zombies
    (never bare kill(pid, 0): it also matches zombies). A missing
    /proc entry counts as exited; an unreadable state fails True
    (fail-closed: an unverifiable sentinel never reads alive)."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1]
        code = state.split()[0]
    except (OSError, IndexError):
        return True
    return code in ("X", "x", "Z")
