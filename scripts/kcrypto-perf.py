#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T14 P9 performance campaign CLI: plan / run / verify / analyze.

One vng guest per pair-set (owned-guest custody, common + task
locks), legs driven by the staged legs.tsv, per-set evidence
cells sealed after writers stop. Budgets and verdict rules are
frozen (docs/bench-thresholds.md, tests/kcrypto_perf/cells.json);
``verify`` judges sealed bytes only and never repairs a run.
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from kcrypto_campaign import owned_guest  # noqa: E402
from kcrypto_campaign import receipt as krecept  # noqa: E402
from kcrypto_perf import stats as kstats  # noqa: E402
from kcrypto_perf import parsers as kparsers  # noqa: E402
from kcrypto_perf import validity as kvalidity  # noqa: E402
from kcrypto_perf import manifest as kmanifest  # noqa: E402
from kcrypto_perf import m1manifest as km1manifest  # noqa: E402
from kcrypto_perf import m1validity as km1validity  # noqa: E402
from kcrypto_perf import successorvalidity as ksucc  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_campaign_cli", str(HERE / "kcrypto-campaign.py"))
_CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLI)

SCENARIOS = HERE / "kcrypto_perf" / "scenarios"
PERF_MANIFEST = HERE.parent / "tests" / "kcrypto_perf" / "cells.json"


def sha256_file(path: Path) -> str:
    return krecept.sha256_file(Path(path))


def load_any_manifest(path: Path) -> dict:
    """Load the frozen or M1 manifest by its declared $schema (the
    $schema read itself is unvalidated JSON; the strict loader for
    the named schema validates everything after)."""
    try:
        declared = json.loads(Path(path).read_bytes()).get("$schema")
    except (OSError, ValueError) as err:
        raise kmanifest.InputError(f"manifest unreadable: {err}") from err
    if declared == km1manifest.SCHEMA:
        return km1manifest.load_manifest(Path(path))
    return kmanifest.load_manifest(Path(path))


def is_m1_manifest(manifest: dict) -> bool:
    """True for M1 early-gate manifests (M1 code paths only)."""
    return manifest.get("$schema") == km1manifest.SCHEMA


def find_set(manifest: dict, set_id: str) -> dict:
    for entry in manifest["sets"]:
        if entry["id"] == set_id:
            return entry
    raise kmanifest.InputError(f"unknown set {set_id!r}")


def find_diag(manifest: dict, diag_id: str) -> dict:
    for entry in manifest["diagnostics"]:
        if entry["id"] == diag_id:
            return entry
    raise kmanifest.InputError(f"unknown diagnostic {diag_id!r}")


def gen_legs(entry: dict, manifest: dict, kind: str, start_pair: int = 0,
             n_pairs: int = -1) -> list:
    """Generate legs.tsv rows for a set or diagnostic.

    Pair-set legs alternate AB/BA from pair 0 (spares continue the
    alternation from ``start_pair``). Returns a list of dicts with
    leg_id/side/mode/cls/driver/size/workload/paced/bulk/threads.
    """
    if entry.get("kind") == "m1-pairs":
        return _gen_m1_legs(entry, manifest, start_pair, n_pairs)
    glob = manifest["global"]
    paced_rate = glob.get("paced_rate_per_s", 1000)
    if kind == "diag":
        return _gen_diag_legs(entry, paced_rate)
    cls = manifest["classes"][entry["class"]]
    driver = cls["driver"]
    size = cls["size"]
    mode = entry["mode"]
    workload = entry["workload"]
    if n_pairs < 0:
        n_pairs = glob["pairs_per_set"]
    legs = []
    if entry.get("kind", "pairs") == "cost-only":
        for i in range(n_pairs):
            legs.append({"leg_id": f"leg{i:02d}B", "side": "B",
                         "mode": mode, "cls": entry["class"],
                         "driver": driver, "size": size,
                         "workload": workload, "paced": paced_rate,
                         "bulk": 0, "threads": 1})
        return legs
    for i in range(n_pairs):
        pair = start_pair + i
        order = ("A", "B") if pair % 2 == 0 else ("B", "A")
        for side in order:
            legs.append({
                "leg_id": f"leg{pair:02d}{side}", "side": side,
                "mode": "disabled" if side == "A" else mode,
                "cls": entry["class"], "driver": driver, "size": size,
                "workload": workload,
                "paced": paced_rate if workload == "paced" else 0,
                "bulk": 0, "threads": 1})
    if entry.get("hosts_bulk") and start_pair == 0:
        pair = start_pair + n_pairs
        order = ("A", "B") if pair % 2 == 0 else ("B", "A")
        for side in order:
            legs.append({
                "leg_id": f"leg{pair:02d}{side}", "side": side,
                "mode": "disabled" if side == "A" else mode,
                "cls": entry["class"], "driver": driver, "size": size,
                "workload": workload, "paced": 0, "bulk": 1, "threads": 1})
    return legs


def _gen_m1_legs(entry: dict, manifest: dict, start_pair: int,
                 n_pairs: int) -> list:
    """M1 pair-set legs: per-side modes (C/R sets observe on both
    sides with different staged artifacts; C/D and R/D keep the
    frozen disabled-A shape). ``threads`` is the judge's
    expected_alloc (never passed to the M1 driver); alternation and
    leg_id shape match the frozen rule exactly."""
    cls = manifest["classes"][entry["class"]]
    workload = manifest["workloads"][entry["workload"]]
    if n_pairs < 0:
        n_pairs = entry["pairs"]
    legs = []
    for i in range(n_pairs):
        pair = start_pair + i
        order = ("A", "B") if pair % 2 == 0 else ("B", "A")
        for side in order:
            legs.append({
                "leg_id": f"leg{pair:02d}{side}", "side": side,
                "mode": entry["mode_a"] if side == "A" else entry["mode_b"],
                "cls": entry["class"], "driver": cls["driver"],
                "size": cls["size"], "workload": entry["workload"],
                "paced": 0, "bulk": 0,
                "threads": workload["driver_threads"]})
    return legs


def _gen_diag_legs(entry: dict, paced_rate: int) -> list:
    if entry["kind"] == "m1-612-ctx":
        return [{"leg_id": "leg00B", "side": "B", "mode": "aggregation",
                 "cls": entry["class"], "driver": "skcipher",
                 "size": entry["size"],
                 "workload": entry["workload"],
                 "paced": 0, "bulk": 0, "threads": 1}]
    if entry["kind"] == "footprint":
        return [{"leg_id": "leg00B", "side": "B", "mode": "attached-idle",
                 "cls": "P-64", "driver": "none", "size": 0,
                 "workload": "idle", "paced": 0, "bulk": 0, "threads": 1}]
    if entry["kind"] == "probe-pairs":
        legs = []
        for pair in range(entry["pairs"]):
            order = ("A", "B") if pair % 2 == 0 else ("B", "A")
            for side in order:
                legs.append({
                    "leg_id": f"leg{pair:02d}{side}", "side": side,
                    "mode": "disabled" if side == "A" else entry["mode"],
                    "cls": entry["class"], "driver": "skcipher", "size": 64,
                    "workload": "paced", "paced": 100, "bulk": 0,
                    "threads": 20})
        return legs
    raise kmanifest.InputError(f"unknown diagnostic kind {entry['kind']!r}")


def cmd_plan(args) -> int:
    manifest = load_any_manifest(Path(args.manifest))
    print(f"manifest {args.manifest} sha={manifest['_manifest_sha256'][:12]}...")
    total_legs = 0
    for entry in manifest["sets"]:
        legs = gen_legs(entry, manifest, "set")
        total_legs += len(legs)
        if entry.get("kind") == "m1-pairs":
            desc = (f"{entry['class']} x {entry['obs_a']}/{entry['mode_a']} "
                    f"vs {entry['obs_b']}/{entry['mode_b']}")
        else:
            desc = f"{entry['class']} x {entry['mode']}"
        print(f"set {entry['id']}: {desc} x "
              f"{entry['kernel']} {entry['workload']} "
              f"budgeted={entry['budgeted']} kind={entry.get('kind', 'pairs')} "
              f"legs={len(legs)}")
    for entry in manifest["diagnostics"]:
        legs = gen_legs(entry, manifest, "diag")
        total_legs += len(legs)
        print(f"diag {entry['id']}: kind={entry['kind']} legs={len(legs)}")
    warm = manifest["global"]["warmup_s"] + manifest["global"]["measure_s"]
    print(f"total {len(manifest['sets'])} sets + "
          f"{len(manifest['diagnostics'])} diagnostics, "
          f"{total_legs} legs (~{total_legs * (warm + 25) // 60} min "
          "measurement+margin, boots extra)")
    return 0


def stage_run_dir(args, entry: dict, manifest: dict, kind: str,
                  manifest_sha: str, vng: str, legs: list,
                  cell_id: str) -> tuple:
    if is_m1_manifest(manifest):
        return stage_m1_run_dir(args, entry, manifest, kind,
                                manifest_sha, vng, legs, cell_id)
    out_root = Path(args.out_root)
    out_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_dir = out_root / cell_id
    if run_dir.exists():
        raise owned_guest.GuestError(
            f"run dir {run_dir} already exists (refusing reuse)")
    run_dir.mkdir(mode=0o700)
    pins: dict = {}
    kryprobe = Path(args.kryprobe).resolve(strict=True)
    shutil.copyfile(kryprobe, run_dir / "kryprobe")
    (run_dir / "kryprobe").chmod(0o755)
    pins["kryprobe"] = sha256_file(run_dir / "kryprobe")
    bpf_dir = Path(args.bpf_dir).resolve(strict=True)
    (run_dir / "kryprobe-bpf").mkdir()
    for obj in ("kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o"):
        shutil.copyfile(bpf_dir / obj, run_dir / "kryprobe-bpf" / obj)
        pins[f"kryprobe-bpf/{obj}"] = sha256_file(
            run_dir / "kryprobe-bpf" / obj)
    driver = Path(args.driver).resolve(strict=True)
    shutil.copyfile(driver, run_dir / "kcrypto_perf.py")
    pins["kcrypto_perf.py"] = sha256_file(run_dir / "kcrypto_perf.py")
    configs = sorted(Path(f"~/.cache/virtme-ng/{vng}/amd64/boot").expanduser()
                     .glob("config-*"))
    if len(configs) != 1:
        raise ValueError(f"want exactly one guest config for {vng}, "
                         f"found {configs}")
    shutil.copyfile(configs[0], run_dir / "guest-config")
    pins["guest-config"] = sha256_file(run_dir / "guest-config")
    need_module = entry.get("class") == "P-ASYNC"
    if need_module:
        ko_map = {}
        for item in args.ko or []:
            key, _, val = item.partition("=")
            if not key or not val:
                raise ValueError(f"bad --ko {item!r}, want K=V")
            ko_map[key] = val
        kernel = entry["kernel"]
        if kernel not in ko_map:
            raise ValueError(f"set {cell_id} needs --ko for {kernel}")
        ko_src = Path(ko_map[kernel]).resolve(strict=True)
        shutil.copyfile(ko_src, run_dir / "kcrypto_fixture.ko")
        pins["kcrypto_fixture.ko"] = sha256_file(
            run_dir / "kcrypto_fixture.ko")
    else:
        pins["kcrypto_fixture.ko"] = "none"
    shutil.copyfile(SCENARIOS / "perf_set.sh", run_dir / "inner.sh")
    pins["inner.sh"] = sha256_file(run_dir / "inner.sh")
    # P9R1A-N6/O-N10: ship the judge itself into the cell so its
    # pins are verifiable post-hoc (the pre-repair validity.py
    # pin named a file that was never staged).
    judge_dir = run_dir / "judge"
    judge_dir.mkdir()
    for src, name in ((HERE / "kcrypto-perf.py", "kcrypto-perf.py"),
                      (HERE / "kcrypto_perf" / "validity.py",
                       "validity.py"),
                      (HERE / "kcrypto_perf" / "stats.py", "stats.py")):
        shutil.copyfile(src, judge_dir / name)
        pins[f"judge/{name}"] = sha256_file(judge_dir / name)
    with (run_dir / "legs.tsv").open("w") as fh:
        for leg in legs:
            fh.write("\t".join(str(leg[key]) for key in
                                ("leg_id", "side", "mode", "cls", "driver",
                                 "size", "workload", "paced", "bulk",
                                 "threads")) + "\n")
    pins["legs.tsv"] = sha256_file(run_dir / "legs.tsv")
    glob = manifest["global"]
    (run_dir / "set.env").write_text(
        f"SET_ID={cell_id}\nCAPTURE_S={glob['capture_s']}\n"
        f"WARMUP_S={glob['warmup_s']}\nMEASURE_S={glob['measure_s']}\n"
        f"SETTLE_S={glob['settle_s']}\nQUIET_S={glob['quiet_s']}\n"
        f"NEED_MODULE={1 if need_module else 0}\n")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE.parent,
                          capture_output=True, text=True,
                          check=True).stdout.strip()
    (run_dir / "head-sha.txt").write_text(head + "\n")
    pins["head-sha.txt"] = sha256_file(run_dir / "head-sha.txt")
    pins["set.env"] = sha256_file(run_dir / "set.env")
    (run_dir / "pins.env").write_text(
        f"ORACLE_SHA={pins['judge/validity.py']}\nCLI_SHA={pins['kryprobe']}\n"
        f"BPF_AGG_SHA={pins['kryprobe-bpf/kcrypto.bpf.o']}\n"
        f"BPF_LC_SHA={pins['kryprobe-bpf/kcrypto-lifecycle.bpf.o']}\n"
        f"MODULE_SHA={pins['kcrypto_fixture.ko']}\n"
        f"DRIVER_SHA={pins['kcrypto_perf.py']}\n")
    pins["pins.env"] = sha256_file(run_dir / "pins.env")
    stage = {"schema": "kcrypto-t14-stage/v1", "cell": cell_id,
             "kind": kind,
             "set": entry["id"] if kind == "set" else None,
             "diag": entry["id"] if kind == "diag" else None,
             "kernel": entry["kernel"], "head": head,
             "manifest_sha256": manifest_sha, "sha256": pins,
             "legs": [leg["leg_id"] for leg in legs]}
    (run_dir / "stage.json").write_text(json.dumps(stage, indent=2) + "\n")
    timeout_s = len(legs) * (glob["capture_s"] + 60) + 600
    return run_dir, stage, timeout_s


def _parse_obs_arg(value: str, side: str) -> tuple:
    """Parse one --obs-A/--obs-B value: the literal DISABLED, or
    ``kryprobe_path:bpf_dir`` (the colon splits on its LAST
    occurrence so paths may contain colons)."""
    if value == "DISABLED":
        return (None, None)
    cli, sep, bpf_dir = value.rpartition(":")
    if not sep or not cli or not bpf_dir:
        raise owned_guest.GuestError(
            f"--obs-{side} wants DISABLED or CLI:BPFDIR, got {value!r}")
    return (Path(cli), Path(bpf_dir))


def m1_stage_metadata_args(obs_roles: dict, metadata_arg):
    """Task05 Stage 4 (freeze G2): the --metadata requirement rule.

    The frozen metadata file is required exactly when a staged
    side has role M (one frozen file for every M leg; per-side
    copies are staged + pinned from it). Fail-closed both ways:
    an M side without --metadata, or --metadata without an M
    side, refuses. Returns the metadata path for M cells, None
    otherwise.
    """
    want = "M" in obs_roles.values()
    if want and not metadata_arg:
        raise owned_guest.GuestError(
            "M1 M side needs --metadata FILE (frozen metadata file)")
    if metadata_arg and not want:
        raise owned_guest.GuestError(
            "--metadata FILE given but no staged side has role M")
    return metadata_arg if want else None


def _precheck_metadata_file(path: Path) -> str:
    """Stage-time metadata gate (freeze G2): regular JSON file with
    the workload-metadata-v1 top-level shape inside the ADR-0012
    §(d) budgets (full schema validation is a host-test gate, not
    a staging gate). Returns the file sha256. Refuses loudly."""
    try:
        raw = Path(path).read_bytes()
    except OSError as err:
        raise owned_guest.GuestError(
            f"--metadata {path}: unreadable: {err}") from err
    if len(raw) > 1048576:
        raise owned_guest.GuestError(
            f"--metadata {path}: {len(raw)} bytes over 1048576")
    try:
        doc = json.loads(raw)
    except ValueError as err:
        raise owned_guest.GuestError(
            f"--metadata {path}: not JSON: {err}") from err
    if not isinstance(doc, dict):
        raise owned_guest.GuestError(
            f"--metadata {path}: top level must be an object")
    for key in ("collector", "snapshot_interval", "kernel_identity",
                "entries"):
        if key not in doc:
            raise owned_guest.GuestError(
                f"--metadata {path}: lacks {key!r}")
    if not isinstance(doc["entries"], list) or \
            len(doc["entries"]) > 1024:
        raise owned_guest.GuestError(
            f"--metadata {path}: entries must be a list <= 1024")
    import hashlib

    return hashlib.sha256(raw).hexdigest()


def stage_m1_run_dir(args, entry: dict, manifest: dict, kind: str,
                     manifest_sha: str, vng: str, legs: list,
                     cell_id: str) -> tuple:
    """Stage one M1 cell: obs-A/obs-B observer dirs (exe + sibling
    kryprobe-bpf/, or a DISABLED marker), the M1 scenario, the M1
    driver, and per-cell driver flags from the manifest workload."""
    out_root = Path(args.out_root)
    out_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_dir = out_root / cell_id
    if run_dir.exists():
        raise owned_guest.GuestError(
            f"run dir {run_dir} already exists (refusing reuse)")
    run_dir.mkdir(mode=0o700)
    pins: dict = {}
    if kind == "set":
        obs_roles = {"A": entry["obs_a"], "B": entry["obs_b"]}
    else:
        obs_roles = {"A": "D", "B": "C"}
    metadata_arg = m1_stage_metadata_args(
        obs_roles, getattr(args, "metadata", None))
    metadata_src = None
    metadata_sha = None
    if metadata_arg is not None:
        metadata_src = Path(metadata_arg).resolve(strict=True)
        metadata_sha = _precheck_metadata_file(metadata_src)
    for side, role in obs_roles.items():
        obs_dir = run_dir / f"obs-{side}"
        obs_dir.mkdir()
        if role == "D":
            (obs_dir / "DISABLED").write_text("disabled side (no observer)\n")
            pins[f"obs-{side}/DISABLED"] = sha256_file(obs_dir / "DISABLED")
            continue
        cli_src, bpf_src = _parse_obs_arg(
            args.obs_a if side == "A" else args.obs_b, side)
        if cli_src is None:
            raise owned_guest.GuestError(
                f"side {side} role {role} needs an observer, got DISABLED")
        cli_src = cli_src.resolve(strict=True)
        bpf_src = bpf_src.resolve(strict=True)
        shutil.copyfile(cli_src, obs_dir / "kryprobe")
        (obs_dir / "kryprobe").chmod(0o755)
        pins[f"obs-{side}/kryprobe"] = sha256_file(obs_dir / "kryprobe")
        (obs_dir / "kryprobe-bpf").mkdir()
        for obj in ("kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o"):
            shutil.copyfile(bpf_src / obj, obs_dir / "kryprobe-bpf" / obj)
            pins[f"obs-{side}/kryprobe-bpf/{obj}"] = sha256_file(
                obs_dir / "kryprobe-bpf" / obj)
        if role == "M":
            # Freeze G2: the frozen metadata bytes + the helper
            # sibling ride the M side (both pinned; the helper is
            # the fixed sibling next to the staged CLI source).
            shutil.copyfile(metadata_src,
                            obs_dir / "workload-metadata.json")
            pins[f"obs-{side}/workload-metadata.json"] = sha256_file(
                obs_dir / "workload-metadata.json")
            helper_src = cli_src.parent / "kryprobe-workload-helper"
            if not helper_src.is_file():
                raise owned_guest.GuestError(
                    f"side {side} role M needs the helper sibling "
                    f"next to {cli_src} (missing/non-regular)")
            helper_src = helper_src.resolve()
            shutil.copyfile(helper_src,
                            obs_dir / "kryprobe-workload-helper")
            (obs_dir / "kryprobe-workload-helper").chmod(0o755)
            pins[f"obs-{side}/kryprobe-workload-helper"] = \
                sha256_file(obs_dir / "kryprobe-workload-helper")
    driver = Path(args.driver).resolve(strict=True)
    shutil.copyfile(driver, run_dir / "kcrypto_perf.py")
    pins["kcrypto_perf.py"] = sha256_file(run_dir / "kcrypto_perf.py")
    configs = sorted(Path(f"~/.cache/virtme-ng/{vng}/amd64/boot").expanduser()
                     .glob("config-*"))
    if len(configs) != 1:
        raise ValueError(f"want exactly one guest config for {vng}, "
                         f"found {configs}")
    shutil.copyfile(configs[0], run_dir / "guest-config")
    pins["guest-config"] = sha256_file(run_dir / "guest-config")
    pins["kcrypto_fixture.ko"] = "none"
    shutil.copyfile(SCENARIOS / "perf_set_m1.sh", run_dir / "inner.sh")
    pins["inner.sh"] = sha256_file(run_dir / "inner.sh")
    judge_dir = run_dir / "judge"
    judge_dir.mkdir()
    for src, name in ((HERE / "kcrypto-perf.py", "kcrypto-perf.py"),
                      (HERE / "kcrypto_perf" / "validity.py",
                       "validity.py"),
                      (HERE / "kcrypto_perf" / "m1validity.py",
                       "m1validity.py"),
                      (HERE / "kcrypto_perf" / "stats.py", "stats.py")):
        shutil.copyfile(src, judge_dir / name)
        pins[f"judge/{name}"] = sha256_file(judge_dir / name)
    with (run_dir / "legs.tsv").open("w") as fh:
        for leg in legs:
            fh.write("\t".join(str(leg[key]) for key in
                                ("leg_id", "side", "mode", "cls", "driver",
                                 "size", "workload", "paced", "bulk",
                                 "threads")) + "\n")
    pins["legs.tsv"] = sha256_file(run_dir / "legs.tsv")
    glob = manifest["global"]
    workload = manifest["workloads"][entry["workload"]]
    (run_dir / "set.env").write_text(
        f"SET_ID={cell_id}\nCAPTURE_S={glob['capture_s']}\n"
        f"WARMUP_S={glob['warmup_s']}\nMEASURE_S={glob['measure_s']}\n"
        f"SETTLE_S={glob['settle_s']}\nQUIET_S={glob['quiet_s']}\n"
        f"NEED_MODULE=0\n"
        # Freeze G2: per-side observer roles (the scenario picks
        # the M capture shape from these) + the frozen metadata
        # digest M legs must run with ("none" without an M side).
        f"OBS_A={obs_roles['A']}\nOBS_B={obs_roles['B']}\n"
        f"METADATA_SHA={metadata_sha or 'none'}\n"
        # F-06: quote — multi-word flags (n_cgroup/churn) must
        # survive `set -u` sourcing as one word (re-split at use).
        f"M1_DRIVER_FLAGS=\"{workload['driver_flags']}\"\n"
        # H-C (A12 item 4): guest-absolute shard root, empty
        # when the manifest carries no shard_dir (frozen
        # ledger-sibling layout); the scenario creates a
        # per-leg subdir under it when non-empty.
        f"M1_SHARD_DIR=\"{glob.get('shard_dir', '')}\"\n")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE.parent,
                          capture_output=True, text=True,
                          check=True).stdout.strip()
    (run_dir / "head-sha.txt").write_text(head + "\n")
    pins["head-sha.txt"] = sha256_file(run_dir / "head-sha.txt")
    pins["set.env"] = sha256_file(run_dir / "set.env")

    def _pin_or_none(name):
        return pins.get(name, "none")

    (run_dir / "pins.env").write_text(
        f"ORACLE_SHA={pins['judge/m1validity.py']}\n"
        f"CLI_A_SHA={_pin_or_none('obs-A/kryprobe')}\n"
        f"BPF_A_AGG_SHA={_pin_or_none('obs-A/kryprobe-bpf/kcrypto.bpf.o')}\n"
        f"BPF_A_LC_SHA={_pin_or_none('obs-A/kryprobe-bpf/kcrypto-lifecycle.bpf.o')}\n"
        f"CLI_B_SHA={_pin_or_none('obs-B/kryprobe')}\n"
        f"BPF_B_AGG_SHA={_pin_or_none('obs-B/kryprobe-bpf/kcrypto.bpf.o')}\n"
        f"BPF_B_LC_SHA={_pin_or_none('obs-B/kryprobe-bpf/kcrypto-lifecycle.bpf.o')}\n"
        f"META_A_SHA={_pin_or_none('obs-A/workload-metadata.json')}\n"
        f"HELPER_A_SHA={_pin_or_none('obs-A/kryprobe-workload-helper')}\n"
        f"META_B_SHA={_pin_or_none('obs-B/workload-metadata.json')}\n"
        f"HELPER_B_SHA={_pin_or_none('obs-B/kryprobe-workload-helper')}\n"
        f"MODULE_SHA={pins['kcrypto_fixture.ko']}\n"
        f"DRIVER_SHA={pins['kcrypto_perf.py']}\n")
    pins["pins.env"] = sha256_file(run_dir / "pins.env")
    stage = {"schema": "kcrypto-t14-stage/v1", "cell": cell_id,
             "kind": kind,
             "set": entry["id"] if kind == "set" else None,
             "diag": entry["id"] if kind == "diag" else None,
             "kernel": entry["kernel"], "head": head,
             "manifest_sha256": manifest_sha, "sha256": pins,
             "obs_a": obs_roles["A"], "obs_b": obs_roles["B"],
             "metadata_sha256": metadata_sha,
             "scenario": "perf_set_m1.sh", "fixture": "kcrypto_perf_m1.py",
             "legs": [leg["leg_id"] for leg in legs]}
    (run_dir / "stage.json").write_text(json.dumps(stage, indent=2) + "\n")
    timeout_s = len(legs) * (glob["capture_s"] + 60) + 600
    return run_dir, stage, timeout_s


RUN_ENV_ALLOWLIST = (
    # Environment variables the runner honors (P9R1A-N10: the
    # receipt-contract identity group requires the allowlist +
    # values, not just argv/cwd).
    "PATH", "KRYPROBE_REQUIRE_PINS", "KRYPROBE_BPF_DIR",
    "CARGO_TEST_CMD", "PYTHONHASHSEED", "SUDO_USER",
)


def _dirty_manifest(worktree: Path) -> tuple:
    """Dirty-file manifest with content hashes (P9R1A-N10).

    Filenames alone prove nothing; each dirty worktree file is
    hashed (deleted files are named as such). Returns (short,
    manifest, unavailable_reason).
    """
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=worktree, capture_output=True, text=True,
            check=True).stdout
    except (subprocess.CalledProcessError, OSError) as err:
        return "UNAVAILABLE", {}, f"git status failed: {err}"
    manifest = {}
    for line in out.splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip().strip('"')
        target = worktree / path
        if target.is_file():
            try:
                manifest[path] = sha256_file(target)
            except OSError as err:
                manifest[path] = f"UNREADABLE: {err}"
        elif target.is_dir():
            manifest[path] = "DIR"
        else:
            manifest[path] = "DELETED"
        if len(manifest) >= 200:
            manifest["..."] = "TRUNCATED at 200 entries"
            break
    short = out.strip()
    return short if short else "clean", manifest, ""


def _host_facts() -> tuple:
    """Host kernel/config/BTF/CPU/load/governor/tracing facts.

    Returns (facts, unavailable): every unreadable fact lands in
    ``unavailable`` with its reason (P9R1A-N10, P9R1O-N7).
    """
    facts: dict = {"kernel": os.uname().release}
    unavailable: dict = {}

    def slurp(path, key, first_line=False, max_len=0):
        try:
            text = Path(path).read_text().strip()
        except OSError as err:
            unavailable[key] = f"{path}: {err}"
            return
        if first_line:
            text = text.splitlines()[0] if text.splitlines() else ""
        if max_len and len(text) > max_len:
            text = text[:max_len] + "...[truncated]"
        facts[key] = text

    try:
        flags = ""
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("flags"):
                flags = line.partition(":")[2].strip()
                break
        if flags:
            facts["cpu_flags"] = flags
        else:
            unavailable["cpu_flags"] = "no flags line in /proc/cpuinfo"
    except OSError as err:
        unavailable["cpu_flags"] = f"/proc/cpuinfo: {err}"
    slurp("/proc/loadavg", "loadavg")
    slurp("/proc/meminfo", "meminfo_head")
    if "meminfo_head" in facts:
        facts["meminfo_head"] = "\n".join(
            facts["meminfo_head"].splitlines()[:3])
    slurp("/proc/cmdline", "cmdline")
    slurp("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
          "governor")
    slurp("/sys/kernel/debug/tracing/tracing_on", "tracing_on")
    try:
        btf = sorted(p.name for p in Path("/sys/kernel/btf").iterdir())
        facts["btf"] = btf
    except OSError as err:
        unavailable["btf"] = f"/sys/kernel/btf: {err}"
    try:
        facts["vmlinux_btf_sha256"] = sha256_file(
            Path("/sys/kernel/btf/vmlinux"))
    except OSError as err:
        unavailable["vmlinux_btf_sha256"] = (
            f"/sys/kernel/btf/vmlinux: {err}")
    for cfg in (f"/boot/config-{os.uname().release}", "/proc/config.gz"):
        try:
            facts["kernel_config_sha256"] = sha256_file(Path(cfg))
            facts["kernel_config_src"] = cfg
            break
        except OSError:
            continue
    else:
        unavailable["kernel_config_sha256"] = "no readable kernel config"
    return facts, unavailable


def _attach_summary(run_dir: Path) -> dict:
    """attach_ready_s min/max across legs (runtime attach results)."""
    ready = []
    timeouts = 0
    for path in sorted((Path(run_dir) / "legs").glob("*-attach.txt")):
        val = _read_attach(path)
        if isinstance(val, int):
            ready.append(val)
        else:
            timeouts += 1
    quiet = _read_attach(Path(run_dir) / "quiet-attach.txt")
    return {"legs": len(ready) + timeouts, "timeouts": timeouts,
            "min_s": min(ready) if ready else None,
            "max_s": max(ready) if ready else None,
            "quiet_s": quiet}


def build_host_receipt(args, entry: dict, manifest: dict, run_dir: Path,
                       stage: dict, result: dict, timeout_s: int) -> dict:
    worktree = HERE.parent
    dirty_short, dirty_manifest, dirty_unavail = _dirty_manifest(worktree)
    try:
        head_tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=worktree,
            capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        head_tree = "UNAVAILABLE"
    try:
        rustc = subprocess.run(["rustc", "--version"], capture_output=True,
                               text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        rustc = "UNAVAILABLE"
    host_facts, host_unavail = _host_facts()
    receipt = krecept.Receipt(
        schema="kcrypto-t14-receipt/v1", run_id=stage["cell"],
        cell_id=stage["cell"], portion_id=stage["cell"])
    receipt.identity = {
        "argv": sys.argv, "cwd": os.getcwd(),
        "source_commit": stage["head"], "source_tree": head_tree,
        "dirty": dirty_short, "dirty_manifest": dirty_manifest,
        "env_allowlist": list(RUN_ENV_ALLOWLIST),
        "env_values": {key: os.environ.get(key, "UNSET")
                       for key in RUN_ENV_ALLOWLIST},
        "artifacts": stage["sha256"],
        "manifest_sha256": stage["manifest_sha256"],
        "toolchain": {"rustc": rustc, "python": sys.version.split()[0]},
    }
    cpu_model = (run_dir / "cpu-model.txt").read_text().strip() \
        if (run_dir / "cpu-model.txt").is_file() else "UNAVAILABLE"
    receipt.environment = {
        "host_kernel": os.uname().release,
        "host": host_facts,
        "guest": _read_kv(run_dir / "environment.txt"),
        "cpu_model": cpu_model,
        "identity_before": _read_kv(run_dir / "identity-before.env"),
        "identity_after": _read_kv(run_dir / "identity-after.env"),
        "attach": _attach_summary(run_dir),
    }
    receipt.input = {
        "set": stage["set"], "diag": stage["diag"],
        "kernel": stage["kernel"], "legs": stage["legs"],
        "scenario": stage.get("scenario", "perf_set.sh"),
        "fixture": stage.get("fixture", "kcrypto_perf.py"),
    }
    receipt.observation = {
        "quiet_calls": _read_kv(run_dir / "quiet-calls.txt").get(
            "quiet_calls"),
        "legs_done": _read_kv(run_dir / "legs-done.txt").get("legs_done"),
        "done": (run_dir / "done.txt").read_text().strip()
        if (run_dir / "done.txt").is_file() else "MISSING",
        "timeout_s": timeout_s,
    }
    receipt.process = {
        "wait": result["wait"], "stop": result["stop"],
        "vng_exit": result["stop"].get("vng_exit"),
        "reaped": result["stop"].get("reaped"),
    }
    receipt.cleanup = {
        "markers": _read_kv(run_dir / "cleanup.txt"),
        "lsmod_after": (run_dir / "lsmod-after.txt").read_text().strip()
        if (run_dir / "lsmod-after.txt").is_file() else "MISSING",
        "remaining_owned_qemu": result["stop"].get("remaining_owned_qemu"),
        "preexisting_qemu_unchanged": result["stop"].get(
            "preexisting_qemu_unchanged"),
    }
    receipt.custody = {
        # P9R1A-N10: name the real seal manifest (cells seal
        # SHA256SUMS, not FILES-SHA256.txt).
        "seal": "SHA256SUMS (written after writers stop)",
        "console": "console.log",
    }
    # P9R1A-N10: no silent unavailable{} — every missing fact
    # carries its reason.
    if dirty_unavail:
        receipt.unavailable["identity.dirty"] = dirty_unavail
    if head_tree == "UNAVAILABLE":
        receipt.unavailable["identity.source_tree"] = \
            "git rev-parse HEAD^{tree} failed"
    if rustc == "UNAVAILABLE":
        receipt.unavailable["identity.toolchain.rustc"] = \
            "rustc --version failed"
    for key, reason in host_unavail.items():
        receipt.unavailable[f"environment.host.{key}"] = reason
    if cpu_model == "UNAVAILABLE":
        receipt.unavailable["environment.cpu_model"] = \
            "guest cpu-model.txt absent"
    return receipt.to_dict()


def _read_kv(path: Path) -> dict:
    out = {}
    try:
        for line in Path(path).read_text().splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                out[key.strip()] = val.strip()
    except OSError:
        out["_missing"] = str(path)
    return out


def cmd_run(args) -> int:
    manifest = load_any_manifest(Path(args.manifest))
    m1 = is_m1_manifest(manifest)
    if m1:
        if not args.obs_a or not args.obs_b:
            print("run: M1 manifest needs --obs-a and --obs-b "
                  "(DISABLED or CLI:BPFDIR)", file=sys.stderr)
            return 2
    elif not args.kryprobe or not args.bpf_dir:
        print("run: frozen manifest needs --kryprobe and --bpf-dir",
              file=sys.stderr)
        return 2
    if args.set:
        entry = find_set(manifest, args.set)
        kind = "set"
        cell_id = args.set if not args.spare else f"{args.set}-spare{args.spare}"
    else:
        entry = find_diag(manifest, args.diag)
        kind = "diag"
        cell_id = args.diag
    start_pair = args.start_pair or 0
    n_pairs = args.pairs if args.pairs is not None else -1
    legs = gen_legs(entry, manifest, kind, start_pair, n_pairs)
    vng = manifest["global"]["vng"][entry["kernel"]]
    run_dir, stage, timeout_s = stage_run_dir(
        args, entry, manifest, kind, manifest["_manifest_sha256"], vng,
        legs, cell_id)
    inner = str(run_dir / "inner.sh")
    name = f"t14-{cell_id}"
    locks = _CLI.resolve_lock_paths(
        [args.lock] if isinstance(args.lock, str) else args.lock)
    first_pin = next(iter(stage["sha256"].values()))
    print(f"staged {run_dir} pins={first_pin[:12]}... "
          f"legs={len(legs)} timeout_s={timeout_s}")
    result = owned_guest.run_cell(
        portion_id=cell_id,
        vng_cmd=["vng", "--run", vng, "--user", "root", "--name", name,
                 "--cpus", str(manifest["global"]["guest_cpus"]),
                 "--memory", manifest["global"]["guest_memory"],
                 "--cwd", "/", "--rwdir", str(run_dir),
                 "--exec", f"sh {inner} {run_dir}"],
        run_dir=run_dir,
        name=name,
        lock_paths=locks,
        timeout_s=timeout_s,
    )
    print(f"wait={result['wait']} reaped={result['stop']['reaped']}")
    receipt = build_host_receipt(args, entry, manifest, run_dir, stage,
                                 result, timeout_s)
    krecept.atomic_write_json(run_dir / "host-receipt.json", receipt)
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    cell_dir = evidence_dir / cell_id
    if cell_dir.exists():
        raise owned_guest.GuestError(
            f"evidence cell {cell_dir} already exists (refusing overwrite)")
    cell_dir.mkdir()
    seal_names = []
    for path in sorted(run_dir.iterdir()):
        if path.is_file():
            shutil.copyfile(path, cell_dir / path.name)
            seal_names.append(path.name)
    subdirs = ("legs", "obs-A", "obs-B", "judge") if m1 \
        else ("legs", "kryprobe-bpf", "judge")
    for sub in subdirs:
        src = run_dir / sub
        if not src.is_dir():
            continue
        if m1:
            # M1 obs dirs nest kryprobe-bpf/ one deeper: seal
            # recursively (frozen subdirs stay flat, see below).
            for path in sorted(src.rglob("*")):
                if path.is_file():
                    rel = path.relative_to(src)
                    dest = cell_dir / sub / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, dest)
                    seal_names.append(f"{sub}/{rel}")
            continue
        (cell_dir / sub).mkdir(exist_ok=True)
        for path in sorted(src.iterdir()):
            if path.is_file():
                shutil.copyfile(path, cell_dir / sub / path.name)
                seal_names.append(f"{sub}/{path.name}")
    krecept.seal_artifacts(cell_dir, seal_names, writers_done=True)
    print(f"sealed {cell_dir} ({len(seal_names)} files)")
    return 0


def _read_int_kv(path: Path, key: str):
    try:
        for line in Path(path).read_text().splitlines():
            name, _, val = line.partition("=")
            if name.strip() == key:
                return int(val.strip())
    except (OSError, ValueError):
        pass
    return None


def _is_positive_int(value) -> bool:
    """Strict positive-int check (N2): real ints only — bools are not
    counters (``True`` is not 1 op), floats/strings/None never pass."""
    return isinstance(value, int) and not isinstance(value, bool) \
        and value > 0


def check_leg_timing(summary: dict, warmup_s: float,
                     measure_s: float) -> list:
    """Enforce the frozen 10 s warm-up + 30 s measurement (P9R1A-N7).

    ``warmup_s``/``measure_s`` come from the frozen manifest
    (bound by sha before judging); the summary's own timestamps
    must land within -1 s (scheduling slack) / +5 s (bounded
    teardown overrun) of them. A zero-warmup/one-second window
    is a protocol violation, never a valid leg.
    """
    try:
        warm_s = (summary["t_meas_start_ns"]
                  - summary["t_warm_start_ns"]) / 1e9
    except (KeyError, TypeError, ArithmeticError):
        return ["timing: driver summary lacks window timestamps"]
    try:
        meas_s = float(summary["meas_window_s"])
    except (KeyError, TypeError, ValueError):
        return ["timing: meas_window_s unreadable"]
    reasons = []
    if not warmup_s - 1.0 <= warm_s <= warmup_s + 5.0:
        reasons.append(
            f"timing: warm {warm_s:.3f}s outside frozen {warmup_s}s "
            "(-1/+5)")
    if not measure_s - 1.0 <= meas_s <= measure_s + 5.0:
        reasons.append(
            f"timing: measure window {meas_s:.3f}s outside frozen "
            f"{measure_s}s (-1/+5)")
    return reasons


def judge_leg(cell_dir: Path, leg: dict, kernel: str,
              windows: tuple, successor: bool = False) -> dict:
    """Judge one staged leg from sealed files (stats + validity).

    ``windows`` is the frozen (warmup_s, measure_s) pair from the
    bound manifest; driver timing must match it (P9R1A-N7).
    ``successor`` selects the v3 successor epoch (freeze A12):
    the frozen per-op exactness check is superseded by the
    truth-equation overlay (misses break per-op equality by
    construction); driver/receipt/timing/loss gates are
    unchanged. Default False keeps every frozen/M1-v2 call
    byte-identical.
    """
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    out = {"leg_id": leg_id, "side": leg["side"], "mode": leg["mode"],
           "cls": leg["cls"], "workload": leg["workload"],
           "bulk": leg["bulk"], "threads": leg["threads"]}
    if leg["mode"] == "attached-idle":
        return judge_idle_leg(cell_dir, leg, out)
    summary_path = legs_dir / f"{leg_id}-driver.csv.summary.json"
    try:
        summary = json.loads(summary_path.read_text())
    except (OSError, ValueError) as err:
        out.update(valid=False, reasons=[f"driver summary: {err}"],
                   outcome="invalid")
        return out
    out["driver"] = {
        "ops_total": summary.get("ops_total"),
        "ops_meas": summary.get("ops_meas"),
        "rows_meas": summary.get("rows_meas"),
        "meas_window_s": summary.get("meas_window_s"),
        "rc": summary.get("rc"), "fails": summary.get("fails"),
        "late": summary.get("late"), "paced": summary.get("paced"),
        "threads": summary.get("threads"),
    }
    out["driver_rc"] = _read_int_kv(legs_dir / f"{leg_id}-driver-rc.txt",
                                    "driver_rc")
    out["driver_timeout"] = _read_int_kv(
        legs_dir / f"{leg_id}-driver-rc.txt", "driver_timeout")
    if out["driver_rc"] is None or out["driver_timeout"] is None:
        out.update(valid=False, reasons=["driver-rc.txt missing/incomplete"],
                   outcome="invalid")
        return out
    # P9R1A-N5: the ACTUAL driver exit (recorded by the shell
    # wrapper) gates the leg — the summary's self-reported rc
    # alone never passes a failed worker.
    if out["driver_rc"] != 0 or summary.get("rc") != 0 or \
            out["driver_timeout"]:
        out.update(valid=False,
                   reasons=[f"driver rc={summary.get('rc')} "
                            f"driver_rc={out['driver_rc']} "
                            f"timeout={out['driver_timeout']} "
                            f"fails={summary.get('fails')}"],
                   outcome="invalid")
        return out
    timing = check_leg_timing(summary, windows[0], windows[1])
    if timing:
        out.update(valid=False, reasons=timing, outcome="invalid")
        return out
    if summary.get("threads", 1) != leg.get("threads", 1):
        out.update(valid=False, reasons=[
            f"threads summary={summary.get('threads')} spec="
            f"{leg.get('threads')}"], outcome="invalid")
        return out
    if leg["bulk"]:
        judge_bulk_leg(summary, out)
        if not out["valid"]:
            return out
        if leg["mode"] == "disabled":
            return out
        return judge_observed_leg(cell_dir, leg, kernel, summary, out,
                                  successor=successor)
    try:
        rows = kparsers.parse_ledger_csv(legs_dir / f"{leg_id}-driver.csv")
    except kparsers.ParseError as err:
        out.update(valid=False, reasons=[str(err)], outcome="invalid")
        return out
    if len(rows) != summary.get("rows_meas"):
        out.update(valid=False, reasons=[
            f"csv rows={len(rows)} summary rows_meas="
            f"{summary.get('rows_meas')}"], outcome="invalid")
        return out
    cls = "async" if leg["driver"] == "async" else leg["driver"]
    try:
        trips = kstats.roundtrip_latencies(rows, cls)
    except ValueError as err:
        out.update(valid=False, reasons=[str(err)], outcome="invalid")
        return out
    del rows
    out["stats"] = {
        "throughput": kstats.throughput(summary["ops_meas"],
                                        summary["meas_window_s"]),
        "p50_ns": kstats.percentile(trips, 50),
        "p99_ns": kstats.percentile(trips, 99),
        "n": len(trips),
    }
    del trips
    if leg["workload"] == "paced":
        offered = summary.get("offered", 0)
        late_frac = (summary.get("late", 0) / offered) if offered else 1.0
        out["paced_late_frac"] = late_frac
        if late_frac > 0.01:
            out.update(valid=False,
                       reasons=[f"paced late_frac={late_frac:.4f} > 0.01"],
                       outcome="invalid")
            return out
    if leg["mode"] == "disabled":
        out.update(valid=True, reasons=[], outcome="valid")
        return out
    return judge_observed_leg(cell_dir, leg, kernel, summary, out,
                              successor=successor)


def judge_bulk_leg(summary: dict, out: dict) -> dict:
    out["stats"] = {
        "throughput": kstats.throughput(summary["ops_meas"],
                                        summary["meas_window_s"]),
        "p50_ns": None, "p99_ns": None, "n": summary.get("ops_meas"),
    }
    if out["driver_rc"] != 0 or out["driver_timeout"] or \
            summary.get("rc") != 0:
        out.update(valid=False, reasons=[
            f"bulk driver rc={summary.get('rc')} "
            f"driver_rc={out['driver_rc']} "
            f"timeout={out['driver_timeout']}"], outcome="invalid")
        return out
    out.update(valid=True, reasons=[], outcome="valid")
    return out


def judge_idle_leg(cell_dir: Path, leg: dict, out: dict) -> dict:
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    capture_rc = _read_int_kv(legs_dir / f"{leg_id}-capture-rc.txt",
                              "capture_rc")
    out["capture_rc"] = capture_rc
    if capture_rc not in (0, 3):
        out.update(valid=False, reasons=[f"capture rc={capture_rc}"],
                   outcome="invalid")
        return out
    try:
        parsed = kparsers.parse_api_returns(
            legs_dir / f"{leg_id}-report.json")
    except kparsers.ParseError as err:
        out.update(valid=False, reasons=[str(err)], outcome="invalid")
        return out
    out["observer"] = observer_metrics(cell_dir, leg, parsed, None)
    out["totals"] = parsed["totals"]
    if parsed["totals"].get("calls") != 0:
        out.update(valid=False,
                   reasons=[f"idle totals calls="
                            f"{parsed['totals'].get('calls')}"],
                   outcome="invalid")
        return out
    out.update(valid=True, reasons=[], outcome="valid")
    return out


def count_progress_ticks(path: Path):
    """Count ``kryprobe: progress`` lines in a capture stderr log
    (Task05 Stage 4, freeze G9: the M-activity poll-cadence
    dimension — the product exports no helper/request counter, so
    the sealed progress cadence stands in, recorded never gated).
    A missing log yields None (unrecorded, never zero)."""
    try:
        text = Path(path).read_text()
    except OSError:
        return None
    return sum(1 for line in text.splitlines()
               if line.startswith("kryprobe: progress "))


def observer_metrics(cell_dir: Path, leg: dict, parsed_agg,
                     parsed_lc, parsed_wl=None) -> dict:
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    metrics: dict = {}
    try:
        sampler = kparsers.parse_sampler(legs_dir / f"{leg_id}-sampler.log")
        metrics["rss_max_kb"] = sampler["rss_max_kb"]
        metrics["cpu_s"] = sampler["cpu_s"]
        metrics["sampler_samples"] = sampler["samples"]
    except kparsers.ParseError as err:
        metrics["sampler_error"] = str(err)
    metrics["attach_ready_s"] = _read_attach(
        legs_dir / f"{leg_id}-attach.txt")
    try:
        tele = kparsers.parse_telemetry(
            legs_dir / f"{leg_id}-capture.stderr.log")
        metrics["lagmax_us"] = tele["lagmax_us"]
        metrics["stop_us"] = (tele["stop"] or {}).get("total_us")
        metrics["stop_spans_us"] = tele["stop"]
        metrics["occupancy"] = tele["occupancy"]
        metrics["telemetry_lines"] = tele["lines"]
        if tele["malformed"]:
            metrics["telemetry_malformed"] = tele["malformed"]
    except kparsers.ParseError as err:
        metrics["telemetry_error"] = str(err)
    if parsed_wl is not None:
        # Freeze G4/G9: M-leg loss equivalents (the workload-json
        # report carries no api-returns loss counters or verdict)
        # plus the M-activity dimensions (typed metadata
        # availability + coverage + poll cadence).
        ledger = parsed_wl["ledger"]
        metrics["loss"] = {
            "gap_unreconciled": ledger["gap_unreconciled"],
            "refused_inserts": ledger["refused_inserts"],
            "system_saturated": ledger["system_saturated"],
            "per_context_saturated":
                ledger["per_context_saturated"],
            "ledger_unknown": ledger["unknown"],
        }
        metrics["wl_metadata_status"] = \
            parsed_wl["metadata"]["status"]
        metrics["wl_metadata_reason"] = \
            parsed_wl["metadata"]["reason"]
        metrics["wl_coverage"] = parsed_wl["coverage"]
        metrics["wl_rows"] = parsed_wl["n_rows"]
        metrics["progress_ticks"] = count_progress_ticks(
            legs_dir / f"{leg_id}-capture.stderr.log")
        report = legs_dir / f"{leg_id}-report.workload-json"
    elif parsed_agg is not None:
        metrics["loss"] = parsed_agg["loss"]
        metrics["verdict"] = parsed_agg["verdict"]
        metrics["lat_nonzero"] = parsed_agg["lat_nonzero"]
        metrics["who_rows"] = len(parsed_agg["who"])
        metrics["stack_ids"] = sorted(
            {(row.get("stack") or {}).get("id")
             for row in parsed_agg["who"]}, key=repr)
        metrics["stack_missing_frames"] = sum(
            1 for row in parsed_agg["who"]
            if not (row.get("stack") or {}).get("frames"))
        report = legs_dir / f"{leg_id}-report.json"
    else:
        receipt = parsed_lc["receipt"]
        metrics["loss"] = receipt["loss"]
        metrics["verdict"] = receipt["verdict"]
        metrics["truncated"] = receipt["truncated"]
        metrics["emitted"] = receipt["emitted"]
        metrics["observations"] = parsed_lc["observations"]
        metrics["terminals"] = parsed_lc["terminals"]
        report = legs_dir / f"{leg_id}-report.jsonl"
    try:
        metrics["report_bytes"] = report.stat().st_size
    except OSError:
        metrics["report_bytes"] = None
    return metrics


def _read_attach(path: Path):
    try:
        text = Path(path).read_text().strip()
    except OSError:
        return None
    _, _, val = text.partition("=")
    val = val.strip()
    if val == "TIMEOUT" or not val:
        return val or None
    try:
        return int(val)
    except ValueError:
        return val


def judge_m_observed_leg(cell_dir: Path, leg: dict, out: dict) -> dict:
    """M-leg observer pass (freeze G4): capture-rc gate +
    workload-json parse + activity metrics. A live workload-json
    capture always exits 3 (the unproven gap + partial capture
    coverage name themselves — 0 is impossible on genuine product
    bytes, so anything but 3 fails closed). The M1 overlay
    (apply_m1_ctx_overlay) runs the M checks proper (report
    shape, ledger, metadata, coverage, ctx cross); this pass only
    establishes that the M-shaped evidence parses. Driver-ledger
    stats were computed format-independently by judge_leg before
    dispatch and are untouched."""
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    capture_rc = _read_int_kv(legs_dir / f"{leg_id}-capture-rc.txt",
                              "capture_rc")
    out["capture_rc"] = capture_rc
    if capture_rc != 3:
        out.update(valid=False,
                   reasons=[f"M capture rc={capture_rc}, want 3 "
                            "(live workload-json always names its "
                            "gap)"],
                   outcome="invalid")
        return out
    try:
        parsed = kparsers.parse_workload_report(
            legs_dir / f"{leg_id}-report.workload-json")
    except kparsers.ParseError as err:
        out.update(valid=False, reasons=[str(err)], outcome="invalid")
        return out
    out["workload"] = parsed
    out["observer"] = observer_metrics(cell_dir, leg, None, None,
                                       parsed_wl=parsed)
    out.update(valid=True, reasons=[], outcome="valid")
    return out


def judge_successor_provisional(cell_dir: Path, leg: dict,
                                kernel: str, parsed: dict,
                                out: dict) -> dict:
    """Successor-epoch R/C pre-gate (freeze A12): everything the
    frozen ``check_leg_agg`` enforces EXCEPT per-op exactness
    (capture rc, class dispatch, destroy-pinned loss gate).
    Per-op equality cannot hold when guard misses skip fexit
    execution, so exactness defers to the truth-equation
    overlay (``apply_successor_overlay``); a leg passing here
    is provisional, never decided."""
    cls = leg["cls"]
    if cls == "P-ASYNC":
        out.update(valid=False, outcome="invalid", reasons=[
            "successor has no proven async truth oracle "
            "(M1 matrix carries no async sets)"])
        return out
    if cls not in kvalidity.AFALG_CLASSES:
        out.update(valid=False, outcome="invalid",
                   reasons=[f"unknown class {cls}"])
        return out
    if out.get("capture_rc") not in kvalidity.VALID_CAPTURE_RC:
        out.update(valid=False, outcome="invalid", reasons=[
            f"capture rc={out.get('capture_rc')}"])
        return out
    threads = leg.get("threads", 1)
    if kernel == "6.12.111":
        destroy = kvalidity.FLOOR_DESTROY_PIN
    else:
        destroy = threads if threads == 1 else None
    # Strict loss evidence: the frozen parser's int() maps
    # False->0 and 0.5->0, so the successor gate re-reads
    # every loss counter strictly instead of trusting the
    # coerced dict.
    try:
        loss = ksucc.parse_loss_counters_strict(
            cell_dir / "legs" / f"{leg['leg_id']}-report.json")
    except ValueError as err:
        out.update(valid=False, reasons=[f"successor loss: {err}"],
                   outcome="invalid")
        return out
    reasons = kvalidity._loss_reasons(loss, destroy)
    # The count supersession keeps the frozen zero-result
    # checks: any row error/queue on a sync leg is
    # unexplained, never absorbed into the equation.
    for key, row in sorted(parsed.get("agg", {}).items(),
                           key=lambda item: str(item[0])):
        if row.get("errors"):
            reasons.append(f"{key[0]} {key[1]} errors="
                           f"{row.get('errors')}")
        if row.get("queued"):
            reasons.append(f"{key[0]} {key[1]} queued="
                           f"{row.get('queued')}")
    for alloc in parsed.get("alloc_rows", []):
        if alloc.get("errors"):
            reasons.append(f"alloc errors={alloc.get('errors')}")
        if alloc.get("queued"):
            reasons.append(f"alloc queued={alloc.get('queued')}")
    if reasons:
        out.update(valid=False, reasons=reasons, outcome="invalid")
        return out
    out["observer"] = observer_metrics(cell_dir, leg, parsed, None)
    out["successor_epoch"] = True
    out.update(valid=True, reasons=[], outcome="valid")
    return out


def judge_observed_leg(cell_dir: Path, leg: dict, kernel: str,
                       summary: dict, out: dict,
                       successor: bool = False) -> dict:
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    capture_rc = _read_int_kv(legs_dir / f"{leg_id}-capture-rc.txt",
                              "capture_rc")
    out["capture_rc"] = capture_rc
    if leg["mode"] == "aggregation":
        if (legs_dir / f"{leg_id}-report.workload-json").is_file():
            # Freeze G4: report-format dispatch by sealed
            # artifact (frozen cells never carry .workload-json);
            # the M1 overlay verifies the format matches the
            # declared observer role (fail-closed both ways).
            return judge_m_observed_leg(cell_dir, leg, out)
        try:
            parsed = kparsers.parse_api_returns(
                legs_dir / f"{leg_id}-report.json")
        except kparsers.ParseError as err:
            out.update(valid=False, reasons=[str(err)], outcome="invalid")
            return out
        threads = leg.get("threads", 1)
        if successor:
            return judge_successor_provisional(
                cell_dir, leg, kernel, parsed, out)
        verdict = kvalidity.check_leg_agg(
            parsed, summary, kernel, leg["cls"], capture_rc,
            expected_alloc=threads, pin_destroy=(threads == 1))
        out["observer"] = observer_metrics(cell_dir, leg, parsed, None)
        out.update(valid=verdict["valid"], reasons=verdict["reasons"],
                   outcome=verdict["outcome"])
        return out
    if leg["mode"] == "full-details":
        try:
            parsed = kparsers.parse_lifecycle(
                legs_dir / f"{leg_id}-report.jsonl")
        except kparsers.ParseError as err:
            out.update(valid=False, reasons=[str(err)], outcome="invalid")
            return out
        expected = summary["ops_total"] * (
            1 if leg["driver"] == "async" else 2)
        verdict = kvalidity.check_leg_details(parsed, expected, leg["cls"])
        out["observer"] = observer_metrics(cell_dir, leg, None, parsed)
        out.update(valid=verdict["valid"], reasons=verdict["reasons"],
                   outcome=verdict["outcome"])
        out["tolerated"] = verdict.get("tolerated", {})
        return out
    out.update(valid=False, reasons=[f"unknown mode {leg['mode']}"],
               outcome="invalid")
    return out


def check_run_receipts(cell_dir: Path) -> tuple:
    """Host wait/reap/completion gates (P9R1A-N5).

    A timed-out, nonzero-exit, or unreaped host run — or an
    incomplete cell (done marker / leg count) — can never yield
    valid legs. Returns (reasons, observed).
    """
    cell_dir = Path(cell_dir)
    try:
        receipt = json.loads(
            (cell_dir / "host-receipt.json").read_text())
    except (OSError, ValueError) as err:
        return [f"host receipt unreadable: {err}"], {}
    reasons = []
    process = receipt.get("process", {})
    cleanup = receipt.get("cleanup", {})
    wait = process.get("wait", {})
    observed = {"wait_exit": wait.get("exit"),
                "timed_out": wait.get("timed_out"),
                "reaped": process.get("reaped"),
                "vng_exit": process.get("vng_exit")}
    if wait.get("timed_out"):
        reasons.append("host run timed out (a timeout cannot pass)")
    if wait.get("exit") != 0:
        reasons.append(f"host wait exit={wait.get('exit')} (want 0)")
    if process.get("reaped") is not True:
        reasons.append("host run was not reaped")
    if process.get("vng_exit") != 0:
        reasons.append(f"vng_exit={process.get('vng_exit')} (want 0)")
    stop = process.get("stop", {})
    if stop.get("remaining_owned_qemu"):
        reasons.append(
            f"remaining owned qemu: {stop.get('remaining_owned_qemu')}")
    if cleanup.get("remaining_owned_qemu"):
        reasons.append(
            "cleanup left owned qemu: "
            f"{cleanup.get('remaining_owned_qemu')}")
    if cleanup.get("preexisting_qemu_unchanged") is not True:
        reasons.append("preexisting qemu changed under the run")
    try:
        done = (cell_dir / "done.txt").read_text().strip()
    except OSError:
        done = "MISSING"
    observed["done"] = done
    if done != "step=done":
        reasons.append(f"done.txt={done!r} (want step=done)")
    try:
        staged = len(parse_legs_tsv(cell_dir / "legs.tsv"))
    except ValueError as err:
        return reasons + [f"legs.tsv: {err}"], observed
    try:
        legs_done = (cell_dir / "legs-done.txt").read_text().strip()
    except OSError:
        legs_done = "MISSING"
    observed["legs_done"] = legs_done
    if legs_done != f"legs_done={staged}":
        reasons.append(f"legs-done {legs_done!r} != staged {staged} legs")
    return reasons, observed


# P9R2A-N01: every staged cell ships these artifacts, so their
# pin rows are mandatory — a removed pin row fails exactly like
# a removed file. ``kcrypto_fixture.ko`` may pin "none" on
# cells that need no module (key present, no file expected).
MANDATORY_STAGE_PINS = frozenset({
    "kryprobe",
    "kryprobe-bpf/kcrypto.bpf.o",
    "kryprobe-bpf/kcrypto-lifecycle.bpf.o",
    "kcrypto_perf.py",
    "inner.sh",
    "guest-config",
    "legs.tsv",
    "head-sha.txt",
    "kcrypto_fixture.ko",
})

# P9R2A-N01: the ONLY pin whose file may be absent without
# failing the cell — the pre-repair judge pin that named a
# ``validity.py`` never shipped into sealed cells. Any other
# missing file fails, even with a consistent re-seal.
HISTORICAL_UNSHIPPED_PINS = frozenset({"validity.py"})

# P9R3A-N01: the ONLY pin that may carry the "none" value —
# the optional fixture module on cells that need no module.
# Any other "none" is a stage defect and fails closed.
NONE_PIN_ALLOWED = frozenset({"kcrypto_fixture.ko"})


def check_stage_pins(cell_dir: Path, stage: dict) -> tuple:
    """Staged pins must equal the sealed bytes + guest hashes (P9R1A-N6).

    A corrupted-then-resealed artifact keeps a consistent seal;
    only the stage binding catches it. Mandatory pin rows must
    be present (P9R2A-N01) and every pinned file except the
    named historical unshipped pin must exist and match. The
    "none" value is allowed ONLY for kcrypto_fixture.ko
    (P9R3A-N01); any other "none" fails closed.
    Returns (reasons, observed).
    """
    cell_dir = Path(cell_dir)
    pins = stage.get("sha256", {}) or {}
    if not pins:
        return ["stage carries no artifact pins"], {}
    reasons = []
    checked = []
    unverifiable = []
    for name in sorted(MANDATORY_STAGE_PINS):
        if name not in pins:
            reasons.append(
                f"pin {name}: mandatory pin key missing from stage")
    for name in sorted(pins):
        pinned = pins[name]
        if pinned == "none":
            if name not in NONE_PIN_ALLOWED:
                reasons.append(
                    f"pin {name}: unexpected \"none\" pin "
                    f"value (fail closed)")
            continue
        target = cell_dir / name
        if not target.is_file():
            if name in HISTORICAL_UNSHIPPED_PINS:
                unverifiable.append(name)
                continue
            reasons.append(
                f"pin {name}: staged file missing from sealed cell")
            continue
        try:
            actual = sha256_file(target)
        except OSError as err:
            reasons.append(f"pin {name}: unreadable: {err}")
            continue
        if actual != pinned:
            reasons.append(
                f"pin {name}: sealed bytes differ from staged pin")
        else:
            checked.append(name)
    env = _read_kv(cell_dir / "environment.txt")
    guest_dims = (("ko", "kcrypto_fixture.ko"),
                  ("obj_agg", "kryprobe-bpf/kcrypto.bpf.o"),
                  ("obj_lc", "kryprobe-bpf/kcrypto-lifecycle.bpf.o"),
                  ("kryprobe", "kryprobe"),
                  ("driver", "kcrypto_perf.py"))
    for dim, pin_name in guest_dims:
        pinned = pins.get(pin_name)
        if pinned is None or pinned == "none":
            continue
        if env.get(dim) != pinned:
            reasons.append(
                f"guest {dim}: in-guest hash differs from staged pin")
    return reasons, {"checked": checked, "unverifiable": unverifiable}


M1_BASE_PINS = frozenset({
    "kcrypto_perf.py",
    "inner.sh",
    "guest-config",
    "legs.tsv",
    "head-sha.txt",
    "set.env",
    "pins.env",
    "kcrypto_fixture.ko",
    "judge/kcrypto-perf.py",
    "judge/validity.py",
    "judge/m1validity.py",
    "judge/stats.py",
})

M1_OBS_PINS = ("kryprobe", "kryprobe-bpf/kcrypto.bpf.o",
               "kryprobe-bpf/kcrypto-lifecycle.bpf.o")

# Freeze G2/G5: M sides additionally pin the frozen metadata file
# bytes + the helper sibling staged next to the CLI.
M1_META_PINS = ("workload-metadata.json", "kryprobe-workload-helper")


def check_m1_stage_pins(cell_dir: Path, stage: dict) -> tuple:
    """M1 stage pins: base pins plus per-side observer pins (a DISABLED
    side pins its marker instead). Guest in-hashes must match staged
    pins per side. Returns (reasons, observed)."""
    cell_dir = Path(cell_dir)
    pins = stage.get("sha256", {}) or {}
    if not pins:
        return ["stage carries no artifact pins"], {}
    reasons = []
    checked = []
    want = set(M1_BASE_PINS)
    for side in ("A", "B"):
        role = stage.get(f"obs_{side.lower()}")
        if role == "D":
            want.add(f"obs-{side}/DISABLED")
        elif role in ("R", "C", "M"):
            for tail in M1_OBS_PINS:
                want.add(f"obs-{side}/{tail}")
            if role == "M":
                for tail in M1_META_PINS:
                    want.add(f"obs-{side}/{tail}")
        else:
            reasons.append(f"stage obs_{side.lower()} role {role!r} unknown")
    for name in sorted(want):
        if name not in pins:
            reasons.append(
                f"pin {name}: mandatory pin key missing from stage")
    for name in sorted(pins):
        pinned = pins[name]
        if pinned == "none":
            if name != "kcrypto_fixture.ko":
                reasons.append(
                    f"pin {name}: unexpected \"none\" pin "
                    "value (fail closed)")
            continue
        target = cell_dir / name
        if not target.is_file():
            reasons.append(
                f"pin {name}: staged file missing from sealed cell")
            continue
        try:
            actual = sha256_file(target)
        except OSError as err:
            reasons.append(f"pin {name}: unreadable: {err}")
            continue
        if actual != pinned:
            reasons.append(
                f"pin {name}: sealed bytes differ from staged pin")
        else:
            checked.append(name)
    env = _read_kv(cell_dir / "environment.txt")
    guest_dims = (("ko", "kcrypto_fixture.ko"),
                  ("driver", "kcrypto_perf.py"))
    for dim, pin_name in guest_dims:
        pinned = pins.get(pin_name)
        if pinned is None or pinned == "none":
            continue
        if env.get(dim) != pinned:
            reasons.append(
                f"guest {dim}: in-guest hash differs from staged pin")
    for side in ("a", "b"):
        for dim, tail in (("kryprobe", "kryprobe"),
                          ("agg", "kryprobe-bpf/kcrypto.bpf.o"),
                          ("lc", "kryprobe-bpf/kcrypto-lifecycle.bpf.o"),
                          ("metadata", "workload-metadata.json"),
                          ("helper", "kryprobe-workload-helper")):
            pin_name = f"obs-{side.upper()}/{tail}"
            pinned = pins.get(pin_name)
            if pinned is None or pinned == "none":
                continue
            if env.get(f"obs_{side}_{dim}") != pinned:
                reasons.append(
                    f"guest obs_{side}_{dim}: in-guest hash differs "
                    "from staged pin")
    # Task05 Stage 4 (M amendment P-E): M sides run from
    # guest-local bytes ($M_LOCAL, uid 4242 — the staged 9p bytes
    # refuse file caps and non-root traversal, C1+C2+C3). The
    # scenario seals the local hashes as m_local_* dims alongside
    # the staged 9p dims; each must equal the same staged pin (one
    # reason line per dim). Non-M sides stage no local bytes, so
    # their m_local dims are never consulted.
    for side in ("a", "b"):
        if (stage.get(f"obs_{side}") or "") != "M":
            continue
        for dim, tail in (("kryprobe", "kryprobe"),
                          ("agg", "kryprobe-bpf/kcrypto.bpf.o"),
                          ("lc",
                           "kryprobe-bpf/kcrypto-lifecycle.bpf.o"),
                          ("metadata", "workload-metadata.json"),
                          ("helper", "kryprobe-workload-helper")):
            pin_name = f"obs-{side.upper()}/{tail}"
            pinned = pins.get(pin_name)
            if pinned is None or pinned == "none":
                continue
            if env.get(f"m_local_{side}_{dim}") != pinned:
                reasons.append(
                    f"guest m_local_{side}_{dim}: in-guest hash "
                    "differs from staged pin")
    return reasons, {"checked": checked, "unverifiable": []}


def judge_m1_quiet(cell_dir: Path, obs_b: str) -> dict:
    """M1 boot-quiet judging (freeze G3/G4): R/C boots parse the
    api-returns quiet report (zero calls); M boots parse the
    workload-json quiet report (system_total zero — the metadata
    state is recorded, never gated: an empty capture answers
    ParseFailed by construction, so gating availability would
    fail a clean boot). Either report present on the wrong boot
    is a mixup (invalid). Returns the quiet verdict dict."""
    cell_dir = Path(cell_dir)
    c_path = cell_dir / "quiet-report.json"
    m_path = cell_dir / "quiet-report.workload-json"
    if obs_b == "M":
        if c_path.is_file():
            return {"valid": False,
                    "reasons": ["M quiet carries quiet-report.json "
                                "(format mixup)"]}
        try:
            parsed = kparsers.parse_workload_report(m_path)
        except kparsers.ParseError as err:
            return {"valid": False,
                    "reasons": [f"quiet leg: {err}"]}
        system = parsed["ledger"]["system_total"]
        out = {"system_total": system,
               "metadata": parsed["metadata"],
               "coverage": parsed["coverage"]}
        if system != 0:
            out.update(valid=False,
                       reasons=[f"quiet leg system_total={system}, "
                                "want 0"])
        else:
            out.update(valid=True, reasons=[])
        return out
    if m_path.is_file():
        return {"valid": False,
                "reasons": [f"{obs_b} quiet carries "
                            "quiet-report.workload-json "
                            "(format mixup)"]}
    try:
        quiet = kparsers.parse_api_returns(c_path)
    except kparsers.ParseError as err:
        return {"valid": False, "reasons": [f"quiet leg: {err}"]}
    check = kvalidity.check_quiet(quiet["totals"])
    return {"totals": quiet["totals"], "valid": check["valid"],
            "reasons": check["reasons"]}


def verify_cell(cell_dir: Path, manifest: dict) -> dict:
    """Judge one sealed cell (legs, quiet, seal, receipts, pins)."""
    cell_dir = Path(cell_dir)
    verdict: dict = {"cell": cell_dir.name, "errors": []}
    seal_ok, seal_info = _CLI.verify_cell_seal(cell_dir)
    verdict["seal_ok"] = seal_ok
    verdict["seal_info"] = seal_info
    if not seal_ok:
        verdict["errors"].append("seal broken")
        return verdict
    try:
        stage = json.loads((cell_dir / "stage.json").read_text())
    except (OSError, ValueError) as err:
        verdict["errors"].append(f"stage.json: {err}")
        return verdict
    verdict["stage"] = {
        "kind": stage.get("kind"), "set": stage.get("set"),
        "diag": stage.get("diag"), "kernel": stage.get("kernel"),
        "manifest_sha256": stage.get("manifest_sha256"),
    }
    if stage.get("manifest_sha256") != manifest["_manifest_sha256"]:
        verdict["errors"].append("manifest drift: cell ran against "
                                f"{stage.get('manifest_sha256')}")
        return verdict
    receipt_reasons, receipt_obs = check_run_receipts(cell_dir)
    verdict["receipt_check"] = receipt_obs
    if receipt_reasons:
        verdict["errors"].extend(receipt_reasons)
        return verdict
    m1 = is_m1_manifest(manifest)
    if m1:
        pin_reasons, pin_obs = check_m1_stage_pins(cell_dir, stage)
    else:
        pin_reasons, pin_obs = check_stage_pins(cell_dir, stage)
    verdict["pin_check"] = pin_obs
    if pin_reasons:
        verdict["errors"].extend(pin_reasons)
        return verdict
    kernel = stage.get("kernel")
    if m1:
        if stage.get("kind") == "set":
            quiet_obs = find_set(manifest, stage["set"])["obs_b"]
        else:
            quiet_obs = "C"
        quiet_check = judge_m1_quiet(cell_dir, quiet_obs)
        verdict["quiet"] = quiet_check
        if not quiet_check["valid"] and quiet_check["reasons"] and \
                quiet_check["reasons"][0].startswith("quiet leg: "):
            verdict["errors"].append(quiet_check["reasons"][0])
            return verdict
    else:
        try:
            quiet = kparsers.parse_api_returns(
                cell_dir / "quiet-report.json")
        except kparsers.ParseError as err:
            verdict["errors"].append(f"quiet leg: {err}")
            return verdict
        quiet_check = kvalidity.check_quiet(quiet["totals"])
        verdict["quiet"] = {"totals": quiet["totals"],
                            "valid": quiet_check["valid"],
                            "reasons": quiet_check["reasons"]}
    try:
        spec = parse_legs_tsv(cell_dir / "legs.tsv")
    except ValueError as err:
        verdict["errors"].append(f"legs.tsv: {err}")
        return verdict
    verdict["spec_boot_invalid"] = not quiet_check["valid"]
    windows = (manifest["global"]["warmup_s"],
               manifest["global"]["measure_s"])
    m1_entry = None
    if m1:
        if stage.get("kind") == "set":
            m1_entry = find_set(manifest, stage["set"])
        else:
            m1_entry = find_diag(manifest, stage["diag"])
    legs = []
    for idx, leg in enumerate(spec):
        # Frozen R1 manifests also version their schema — the
        # successor epoch additionally requires an M1 pairs
        # entry with a C/M role (never R, never diags).
        successor = m1 and m1_entry is not None and _successor_leg(
            manifest, leg, m1_entry)
        judged = judge_leg(cell_dir, leg, kernel, windows,
                           successor=successor)
        judged["order"] = idx
        if m1:
            judged = apply_m1_ctx_overlay(cell_dir, judged, leg, m1_entry,
                                          manifest, kernel=kernel)
            for reason in check_m_evidence(cell_dir, leg, m1_entry,
                                           stage):
                judged["valid"] = False
                judged["outcome"] = "invalid"
                judged["reasons"] = judged.get("reasons", []) + \
                    [reason]
        if not quiet_check["valid"]:
            judged["valid"] = False
            judged["outcome"] = "invalid"
            judged["reasons"] = (judged.get("reasons", []) +
                                 ["boot quiet failed"])
        legs.append(judged)
    verdict["legs"] = legs
    return verdict


def apply_successor_overlay(cell_dir: Path, judged: dict,
                            leg: dict, manifest: dict, kernel: str,
                            obs: str) -> dict:
    """Successor truth-equation gate (freeze A12, manifest v3
    only — the caller gates on the epoch). Runs after the M1
    overlay passes: the driver truth oracle (``successor_truth``
    over the judged driver summary) against the report +
    stderr miss operands, with the per-program lane pin from
    the v3 manifest. Async legs refuse (no proven oracle).
    Decided operands land on ``judged["successor"]`` for the
    receipt."""
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]

    def fail(reason):
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [reason]
        return judged

    if leg.get("cls") == "P-ASYNC":
        return fail("successor has no proven async truth oracle "
                    "(M1 matrix carries no async sets)")
    ops = judged.get("driver", {}).get("ops_total")
    if not _is_positive_int(ops):
        return fail(f"successor driver ops_total unreadable: {ops!r}")
    alloc = leg.get("threads", 1)
    if not _is_positive_int(alloc):
        return fail(f"successor alloc (threads) unreadable: {alloc!r}")
    try:
        truth = ksucc.successor_truth(ops=ops, alloc=alloc,
                                      kernel=kernel)
    except ValueError as err:
        return fail(f"successor truth oracle: {err}")
    pin = manifest.get("global", {}).get("expected_programs")
    if type(pin) is not int or pin <= 0:
        return fail("successor v3 manifest lacks global "
                    f"expected_programs (got {pin!r})")
    stderr_log = legs_dir / f"{leg_id}-capture.stderr.log"
    try:
        miss = ksucc.parse_miss_telemetry(stderr_log)
    except ValueError as err:
        return fail(f"successor miss telemetry: {err}")
    # The frozen decoders last-win duplicate members, so the
    # v3 path re-validates the driver summary (truth source)
    # and — for M — the workload report bytes strictly. v2
    # keeps frozen decoder behavior (strict JSON is a v3
    # successor rule only).
    try:
        ksucc.load_strict_json(
            legs_dir / f"{leg_id}-driver.csv.summary.json")
    except ValueError as err:
        return fail(f"successor driver summary: {err}")
    if obs == "M":
        try:
            ksucc.load_strict_json(
                legs_dir / f"{leg_id}-report.workload-json")
        except ValueError as err:
            return fail(f"successor workload report: {err}")
        parsed = judged.get("workload")
        ctx = judged.get("ctx")
        if parsed is None or ctx is None:
            return fail("successor M leg lacks judged workload/ctx "
                        "(M overlay must run first)")
        reasons = ksucc.check_successor_m_leg(
            parsed, ctx, miss_delta=miss["miss_delta"], truth=truth,
            programs=miss["programs"], expected_programs=pin)
        judged["successor"] = {
            "observed": parsed["ledger"]["system_total"],
            "truth": truth, "miss_delta": miss["miss_delta"],
            "programs": miss["programs"]}
    else:
        report_path = legs_dir / f"{leg_id}-report.json"
        # kernel_misses belongs to aggregate_counts only: a
        # detailed_events twin is a contradictory receipt.
        try:
            twin = ksucc.report_has_counter(
                report_path, "detailed_events", "kernel_misses")
        except ValueError as err:
            return fail(f"successor report operands: {err}")
        if twin:
            return fail("successor report operands: kernel_misses "
                        "counter in detailed_events (anomaly)")
        try:
            parsed = kparsers.parse_api_returns(report_path)
            km = ksucc.parse_kernel_misses_counter(report_path)
            snap = ksucc.parse_snapshot_counters(report_path)
            agg_sum = ksucc.agg_calls_sum(parsed.get("agg", {}),
                                          parsed.get("alloc_rows", []))
        except (kparsers.ParseError, ValueError) as err:
            return fail(f"successor report operands: {err}")
        observed = parsed["totals"].get("calls")
        snap_reasons = ksucc.check_snapshot_agreement(
            totals=observed,
            snapshot_agg=snap["snapshot_agg_calls"],
            snapshot_totals=snap["snapshot_totals_calls"],
            agg_sum=agg_sum)
        if snap_reasons:
            judged["valid"] = False
            judged["outcome"] = "invalid"
            judged["reasons"] = judged.get("reasons", []) + \
                snap_reasons
            return judged
        reasons = ksucc.check_successor_leg(
            observed=observed, truth=truth, report_misses=km,
            stderr_miss_delta=miss["miss_delta"],
            ktot_gap=snap["ktot_gap"], programs=miss["programs"],
            expected_programs=pin)
        judged["successor"] = {
            "observed": observed, "truth": truth,
            "kernel_misses": km, "miss_delta": miss["miss_delta"],
            "ktot_gap": snap["ktot_gap"],
            "programs": miss["programs"]}
    if reasons:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + reasons
    return judged


def _m1_leg_obs(leg: dict, entry: dict):
    """Observer role for one M1 leg (pairs entries only; diag
    kinds adjudicate separately and return None)."""
    if entry.get("kind") == "m1-pairs":
        side = leg["side"]
        return entry["obs_a"] if side == "A" else entry["obs_b"]
    return None


def _successor_leg(manifest: dict, leg: dict, entry: dict) -> bool:
    """True when one leg judges under the successor epoch: v3
    manifest and a C/M pairs role. R legs keep frozen per-op
    exactness on every epoch (A12 D2: R1 bytes predate miss
    surfacing, and frozen exactness is the stricter gate —
    any R-side miss fails it); diag kinds keep their frozen
    adjudication."""
    if manifest.get("manifest_version") != 3:
        return False
    return _m1_leg_obs(leg, entry) in ("C", "M")


def apply_m1_ctx_overlay(cell_dir: Path, judged: dict, leg: dict,
                         entry: dict, manifest: dict,
                         kernel: str = None) -> dict:
    """M1 ctx attribution overlay on one frozen-judged leg.

    C-side observed legs must carry the terminal ctx object and pass
    the per-shape exactness rules; R-side observed legs must NOT
    carry one (an R leg with ctx means artifact mixup — invalid).
    Disabled legs pass through with their observer role recorded."""
    side = leg["side"]
    if entry.get("kind") == "m1-pairs":
        obs = entry["obs_a"] if side == "A" else entry["obs_b"]
    else:
        obs = "C" if side == "B" else "D"
    judged["obs"] = obs
    if leg["mode"] == "disabled" or obs == "D":
        # A12 D3 covers every successor input including the
        # disabled baseline: v3 pairs-D summaries
        # re-validate strictly (diag fallbacks and v1/v2
        # keep frozen decoder behavior).
        if manifest.get("manifest_version") == 3 and \
                entry.get("kind") == "m1-pairs":
            try:
                ksucc.load_strict_json(
                    cell_dir / "legs" /
                    f"{leg['leg_id']}-driver.csv.summary.json")
            except ValueError as err:
                judged["valid"] = False
                judged["outcome"] = "invalid"
                judged["reasons"] = judged.get("reasons", []) + [
                    f"successor driver summary: {err}"]
        return judged
    if entry.get("kind") == "m1-612-ctx":
        # F3: the diag's C leg is frozen-invalid BY DESIGN — the diag
        # adjudicates attach + ctx directly, never via leg["valid"].
        return apply_m1_diag_overlay(cell_dir, judged, leg)
    if not judged.get("valid") or "driver" not in judged:
        # Frozen-invalid already (or no driver summary): keep the
        # frozen reasons focused, skip the ctx overlay.
        return judged
    legs_dir = cell_dir / "legs"
    stderr_log = legs_dir / f"{leg['leg_id']}-capture.stderr.log"
    if obs == "R":
        try:
            km1validity.parse_ctx_telemetry(stderr_log)
        except ValueError:
            # A12 D2: R keeps frozen per-op exactness (already
            # judged in the chain) — never the truth equation.
            # But any present R-side miss surface invalidates:
            # R1 bytes cannot emit one, so presence is an
            # anomaly (wrong bytes staged as R, or future
            # R-side loss that frozen exactness must see).
            if manifest.get("manifest_version") == 3 and \
                    entry.get("kind") == "m1-pairs":
                surfaces = []
                report_path = legs_dir / f"{leg['leg_id']}-report.json"
                try:
                    for dim in ("aggregate_counts",
                                "detailed_events"):
                        if ksucc.report_has_counter(
                                report_path, dim, "kernel_misses"):
                            surfaces.append(f"{dim} kernel_misses")
                except ValueError as err:
                    judged["valid"] = False
                    judged["outcome"] = "invalid"
                    judged["reasons"] = judged.get("reasons", []) + [
                        f"successor R report malformed: {err}"]
                    return judged
                if ksucc.stderr_has_misses(stderr_log):
                    surfaces.append("stderr misses")
                if surfaces:
                    judged["valid"] = False
                    judged["outcome"] = "invalid"
                    judged["reasons"] = judged.get("reasons", []) + [
                        "successor R-side miss evidence "
                        f"({' + '.join(surfaces)} present): R1 "
                        "bytes cannot surface misses"]
                    return judged
                # A12 D3 covers every successor input: the v3
                # R summary re-validates strictly too (R
                # keeps frozen per-op exactness, not frozen
                # decoder behavior).
                try:
                    ksucc.load_strict_json(
                        legs_dir / f"{leg['leg_id']}-driver.csv."
                        "summary.json")
                except ValueError as err:
                    judged["valid"] = False
                    judged["outcome"] = "invalid"
                    judged["reasons"] = judged.get("reasons", []) + [
                        f"successor driver summary: {err}"]
                    return judged
            return judged
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [
            "R leg carries a ctx object (artifact mixup: C staged as R?)"]
        return judged
    if obs == "M":
        return apply_m1_m_overlay(cell_dir, judged, leg, entry,
                                  manifest, kernel=kernel)
    wl_path = legs_dir / f"{leg['leg_id']}-report.workload-json"
    if wl_path.is_file():
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [
            "C leg carries a workload-json report (artifact mixup: "
            "M staged as C?)"]
        return judged
    try:
        ctx = km1validity.parse_ctx_telemetry(stderr_log)
    except ValueError as err:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [str(err)]
        return judged
    judged["ctx"] = ctx
    judged["unknown_fraction"] = km1validity.unknown_fraction(ctx)
    report_path = legs_dir / f"{leg['leg_id']}-report.json"
    try:
        parsed = kparsers.parse_api_returns(report_path)
    except kparsers.ParseError as err:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [str(err)]
        return judged
    try:
        ctx_overflow = km1validity.parse_ctx_overflow_counter(report_path)
    except ValueError as err:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [str(err)]
        return judged
    judged["ctx_overflow_identities"] = ctx_overflow
    shape = leg["workload"]
    # Diag legs never reach here (apply_m1_diag_overlay above).
    expected_rows = manifest["workloads"][shape]["expected_rows"]
    reasons = km1validity.check_ctx_leg(
        ctx, parsed["totals"].get("calls"), shape, expected_rows,
        ctx_overflow=ctx_overflow)
    if reasons:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + reasons
        return judged
    if _successor_leg(manifest, leg, entry):
        return apply_successor_overlay(cell_dir, judged, leg,
                                       manifest, kernel, obs)
    return judged


def apply_m1_m_overlay(cell_dir: Path, judged: dict, leg: dict,
                       entry: dict, manifest: dict,
                       kernel: str = None) -> dict:
    """M-leg overlay (freeze G4/G6): the workload-json report must
    exist (an M-role leg with only C-shaped evidence is a leg run
    without the metadata path — invalid, never silently a C leg),
    then the M report rules (shape, ledger, metadata, coverage,
    refused overflow), the terminal ctx walk, the same-walk
    ledger↔ctx cross-equalities, and the per-shape ctx exactness
    rules with refused_inserts as the overflow operand (the
    workload-json report carries no ctx_overflow_identities
    counter; refused_inserts is the same KCTX_DROPS counter under
    both walks)."""
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    wl_path = legs_dir / f"{leg_id}-report.workload-json"
    if not wl_path.is_file():
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [
            "M leg has no workload-json report (C staged as M?)"]
        return judged
    try:
        parsed = kparsers.parse_workload_report(wl_path)
    except kparsers.ParseError as err:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [str(err)]
        return judged
    judged["workload"] = parsed
    shape = leg["workload"]
    reasons = km1validity.check_m_report(parsed, shape)
    if reasons:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + reasons
        return judged
    stderr_log = legs_dir / f"{leg_id}-capture.stderr.log"
    try:
        ctx = km1validity.parse_ctx_telemetry(stderr_log)
    except ValueError as err:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + [str(err)]
        return judged
    judged["ctx"] = ctx
    judged["unknown_fraction"] = km1validity.unknown_fraction(ctx)
    reasons = km1validity.check_m_cross(parsed, ctx)
    if reasons:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + reasons
        return judged
    expected_rows = manifest["workloads"][shape]["expected_rows"]
    reasons = km1validity.check_ctx_leg(
        ctx, parsed["ledger"]["system_total"], shape, expected_rows,
        ctx_overflow=parsed["ledger"]["refused_inserts"],
        counter_name="refused_inserts")
    if reasons:
        judged["valid"] = False
        judged["outcome"] = "invalid"
        judged["reasons"] = judged.get("reasons", []) + reasons
        return judged
    if _successor_leg(manifest, leg, entry):
        return apply_successor_overlay(cell_dir, judged, leg,
                                       manifest, kernel, "M")
    return judged


def check_m_evidence(cell_dir: Path, leg: dict, entry: dict,
                     stage: dict) -> list:
    """Per-leg M-active proof (Task05 Stage 4, freeze G6). Every M
    leg must carry its sealed legs/LEG-m.json launch audit with
    the exact staged metadata/helper shas and a non-root
    principal; anything else (missing file, sha mismatch, uid 0,
    schema/identity mismatch) is invalid with the gap named, so
    an M-without-metadata leg can never pass as M. Non-M legs
    must NOT carry the audit (a present file is a mixup). Returns
    reasons (empty = proven/absent-as-expected)."""
    side = leg["side"]
    if entry.get("kind") == "m1-pairs":
        obs = entry["obs_a"] if side == "A" else entry["obs_b"]
    else:
        obs = "C" if side == "B" else "D"
    m_path = Path(cell_dir) / "legs" / f"{leg['leg_id']}-m.json"
    if obs != "M":
        if m_path.is_file():
            return [f"{leg['leg_id']}-m.json present on a {obs} "
                    "leg (M audit mixup)"]
        return []
    if leg.get("mode") == "disabled":
        return ["M leg with disabled mode (staging contradiction)"]
    if not m_path.is_file():
        return [f"M leg {leg['leg_id']} lacks {leg['leg_id']}-m.json "
                "(no M-active audit)"]
    try:
        audit = json.loads(m_path.read_text())
    except (OSError, ValueError) as err:
        return [f"M leg {leg['leg_id']}-m.json unreadable: {err}"]
    if not isinstance(audit, dict):
        return [f"M leg {leg['leg_id']}-m.json not an object"]
    if audit.get("schema") != "kryprobe-m1-mleg/v1":
        return [f"M leg {leg['leg_id']}-m.json schema "
                f"{audit.get('schema')!r} refused"]
    for key, want in (("leg_id", leg["leg_id"]), ("side", side),
                      ("obs", "M")):
        if audit.get(key) != want:
            return [f"M leg {leg['leg_id']}-m.json {key}="
                    f"{audit.get(key)!r}, want {want!r}"]
    pins = (stage.get("sha256") or {})
    reasons = []
    for key, tail in (("metadata_sha256", "workload-metadata.json"),
                      ("helper_sha256", "kryprobe-workload-helper")):
        pinned = pins.get(f"obs-{side}/{tail}")
        if pinned is None or pinned == "none":
            reasons.append(f"M leg {key}: no staged pin "
                           f"obs-{side}/{tail}")
        elif audit.get(key) != pinned:
            reasons.append(f"M leg {key}={audit.get(key)!r} differs "
                           "from the staged pin")
    uid = audit.get("principal_uid")
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        reasons.append(f"M leg principal_uid={uid!r}: M legs run "
                       "as non-root (uid 0 has no principal and "
                       "never launches the helper)")
    return reasons


def apply_m1_diag_overlay(cell_dir: Path, judged: dict,
                          leg: dict) -> dict:
    """m1-612-ctx evidence extraction (F3): attach audit + terminal ctx
    + report totals + A2 exactness, stashed under ``judged["diag"]``
    WITHOUT consulting the frozen shape verdict (aggregation mode +
    6.12-floor subject shape never satisfy ``check_leg_agg`` — that is
    the diag's subject, not its failure). Any unreadable evidence is
    recorded as a ``*_error`` key; ``judge_m1_diag`` turns every such
    key into an INVALID reason (fail-closed)."""
    legs_dir = cell_dir / "legs"
    stderr_log = legs_dir / f"{leg['leg_id']}-capture.stderr.log"
    diag: dict = {}
    try:
        diag["attach"] = km1validity.parse_attach_audit(stderr_log)
    except ValueError as err:
        diag["attach_error"] = str(err)
    try:
        ctx = km1validity.parse_ctx_telemetry(stderr_log)
    except ValueError as err:
        diag["ctx_error"] = str(err)
        judged["diag"] = diag
        return judged
    diag["ctx"] = ctx
    judged["ctx"] = ctx
    judged["unknown_fraction"] = km1validity.unknown_fraction(ctx)
    report_path = legs_dir / f"{leg['leg_id']}-report.json"
    try:
        parsed = kparsers.parse_api_returns(report_path)
    except kparsers.ParseError as err:
        diag["report_error"] = str(err)
        judged["diag"] = diag
        return judged
    diag["totals_calls"] = parsed["totals"].get("calls")
    try:
        diag["ctx_overflow_identities"] = \
            km1validity.parse_ctx_overflow_counter(report_path)
    except ValueError as err:
        diag["overflow_error"] = str(err)
        judged["diag"] = diag
        return judged
    # Row pin skipped (diag kind): the floor splits kh across cryptd
    # arms, so exactness without a row-shape claim is the honest check.
    diag["exactness"] = km1validity.check_ctx_leg(
        ctx, parsed["totals"].get("calls"), leg["workload"], None,
        ctx_overflow=diag["ctx_overflow_identities"])
    judged["diag"] = diag
    return judged


def parse_legs_tsv(path: Path) -> list:
    legs = []
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as err:
        raise ValueError(f"legs.tsv unreadable: {err}") from err
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 10:
            raise ValueError(f"legs.tsv:{lineno}: want 10 columns")
        (leg_id, side, mode, cls, driver, size, workload, paced, bulk,
         threads) = parts
        try:
            legs.append({"leg_id": leg_id, "side": side, "mode": mode,
                         "cls": cls, "driver": driver, "size": int(size),
                         "workload": workload, "paced": int(paced),
                         "bulk": int(bulk), "threads": int(threads)})
        except ValueError as err:
            raise ValueError(
                f"legs.tsv:{lineno}: bad numerics: {err}") from err
    return legs


def expected_first_side(pair_key: str):
    """Frozen AB/BA alternation: even pairs start A, odd start B.

    Pair numbers encode the global pair index (spares continue
    the numbering), so parity holds across cells. Bulk pairs and
    non-pair keys are exempt (None).
    """
    if len(pair_key) == 5 and pair_key.startswith("leg") and \
            pair_key[3:].isdigit():
        return "A" if int(pair_key[3:]) % 2 == 0 else "B"
    return None


def form_pairs(cell_verdicts: list) -> list:
    """Form ordered pairs across a set's cells (spares continue)."""
    by_pair: dict = {}
    order: dict = {}
    for verdict in cell_verdicts:
        for leg in verdict.get("legs", []):
            leg_id = leg["leg_id"]
            if leg.get("bulk"):
                key = f"bulk-{leg_id[:5]}"
            else:
                key = leg_id[:5]
            slot = by_pair.setdefault(key, {})
            slot[leg["side"]] = leg
            order.setdefault(key, len(order))
    pairs = []
    for key in sorted(order, key=order.get):
        slot = by_pair[key]
        if set(slot) != {"A", "B"}:
            pairs.append({"pair": key, "valid": False,
                          "reasons": [f"sides present {sorted(slot)}"],
                          "legs": {side: slot[side]["leg_id"]
                                   for side in slot}})
            continue
        leg_a, leg_b = slot["A"], slot["B"]
        check = kvalidity.check_pair(leg_a["valid"], leg_b["valid"])
        order = ("A", "B") if leg_a.get("order", 0) < leg_b.get(
            "order", 0) else ("B", "A")
        pair = {"pair": key, "valid": check["valid"],
                "reasons": list(check["reasons"]),
                "legs": {"A": leg_a["leg_id"], "B": leg_b["leg_id"]},
                "order": order}
        if not leg_a.get("bulk"):
            # P9R1A-N7: the frozen protocol runs alternating
            # pairs; a non-alternating order is never a valid
            # pair, however clean its legs.
            want = expected_first_side(key)
            if want is not None and order[0] != want:
                pair["valid"] = False
                pair["reasons"].append(
                    f"order {order} violates frozen alternation: "
                    f"pair {key} must start with {want}")
        if pair["valid"] and not leg_a.get("bulk"):
            pair["ratios"] = {
                "throughput": (leg_b["stats"]["throughput"] /
                               leg_a["stats"]["throughput"]),
                "p50": leg_b["stats"]["p50_ns"] / leg_a["stats"]["p50_ns"],
                "p99": leg_b["stats"]["p99_ns"] / leg_a["stats"]["p99_ns"],
            }
            pair["observer_b"] = leg_b.get("observer")
        pairs.append(pair)
    return pairs


def judge_set(set_id: str, cell_verdicts: list, manifest: dict) -> dict:
    """Combine a set's cells (incl. spares) into the set verdict."""
    entry = find_set(manifest, set_id)
    if entry.get("kind") == "m1-pairs":
        return judge_m1_set(set_id, entry, cell_verdicts, manifest)
    out: dict = {"set": set_id, "class": entry["class"],
                 "mode": entry["mode"], "kernel": entry["kernel"],
                 "budgeted": entry["budgeted"],
                 "kind": entry.get("kind", "pairs")}
    for verdict in cell_verdicts:
        if verdict.get("errors"):
            out.update(verdict="INVALID",
                       reasons=[f"{verdict['cell']}: {verdict['errors']}"])
            return out
    if entry.get("kind", "pairs") == "cost-only":
        legs = [leg for verdict in cell_verdicts
                for leg in verdict.get("legs", [])]
        out["legs"] = [{key: leg.get(key) for key in
                        ("leg_id", "valid", "outcome", "reasons", "stats",
                         "observer")} for leg in legs]
        out.update(verdict="ENVELOPE",
                   reasons=["cost-only: no pairs by design"])
        return out
    pairs = form_pairs(cell_verdicts)
    main = [pair for pair in pairs if not pair["pair"].startswith("bulk-")]
    bulk = [pair for pair in pairs if pair["pair"].startswith("bulk-")]
    out["pairs"] = pairs
    set_check = kvalidity.check_set([pair["valid"] for pair in main])
    out["set_check"] = set_check
    if not set_check["qualified"]:
        out.update(verdict="INVALID",
                   reasons=[f"only {set_check['valid_pairs']}/"
                            f"{set_check['attempted_pairs']} valid pairs"])
        return out
    ratios_t = [pair["ratios"]["throughput"] for pair in main
                if pair["valid"]]
    ratios_p99 = [pair["ratios"]["p99"] for pair in main if pair["valid"]]
    out["medians"] = {"throughput": kstats.median(ratios_t),
                      "p99": kstats.median(ratios_p99)}
    if bulk:
        out["perturbation"] = perturbation_report(cell_verdicts, bulk)
    if entry["budgeted"]:
        budgets = manifest["budgets"]
        b1 = kstats.set_verdict(
            ratios_t, lo=budgets["B1_throughput_ratio_min"], hi=None)
        b2 = kstats.set_verdict(
            ratios_p99, lo=None, hi=budgets["B2_p99_ratio_max"])
        out["B1"] = b1
        out["B2"] = b2
        if b1 == "PASS" and b2 == "PASS":
            out.update(verdict="PASS", reasons=[])
        elif b1 == "FAIL" or b2 == "FAIL":
            out.update(verdict="FAIL",
                       reasons=[f"B1={b1} B2={b2}"])
        else:
            out.update(verdict="INCONCLUSIVE",
                       reasons=[f"B1={b1} B2={b2}"])
    else:
        out.update(verdict="ENVELOPE",
                   reasons=["non-budget set: envelope published"])
    return out


def audit_m1_attempt_ids(cell_verdicts: list) -> list:
    """M1 raw-attempt identity audit (N4), BEFORE frozen pairing.

    ``form_pairs`` is frozen: it silently overwrites ``slot[side]``
    on duplicate leg_ids and ``attempted`` counts deduplicated
    pairs — a mistyped spare ``--start-pair`` would substitute
    evidence and defeat the attempt budget. The audit rejects:
    duplicate leg_ids across the set's cells, malformed leg_ids
    (legs.tsv carries no shape check — want ``legNN{A,B}``), and
    gapped pair indices (staging always numbers contiguously from
    0: main 00..N, spares continue — runbook per-class starts).
    Missing sides per index stay with frozen pairing (invalid
    pairs fail quorum). Empty leg lists pass vacuously (quorum
    INVALIDs them downstream anyway).
    """
    seen: set = set()
    dupes: set = set()
    malformed: set = set()
    indices: set = set()
    for verdict in cell_verdicts:
        for leg in verdict.get("legs", []):
            leg_id = leg.get("leg_id", "")
            if leg_id in seen:
                dupes.add(leg_id)
            seen.add(leg_id)
            if len(leg_id) == 6 and leg_id.startswith("leg") \
                    and leg_id[3:5].isdigit() and leg_id[5] in "AB":
                indices.add(int(leg_id[3:5]))
            else:
                malformed.add(leg_id)
    reasons = []
    if dupes:
        reasons.append(f"duplicate attempt leg_ids: {sorted(dupes)} "
                       "(spare restaged main attempts?)")
    if malformed:
        reasons.append(f"malformed attempt leg_ids: {sorted(malformed)} "
                       "(want legNN{{A,B}})")
    if indices != set(range(len(indices))):
        reasons.append(f"non-contiguous attempt indices: have "
                       f"{sorted(indices)} (want 0..{len(indices) - 1})")
    return reasons


M1_FLOOR_4K = 0.80


def eval_m1_disabled_floor(entry: dict, ratios_t: list):
    """ADR-0019 0.80 4K disabled-relative floor (Task05 Stage 4,
    freeze G7): evaluated on unbudgeted 4K D-vs-observer sets
    (C/M legs vs disabled), reported alongside the ENVELOPE
    medians, never a PASS/FAIL. Same median+80% shape as the
    frozen budgets: the floor holds iff the median is inside
    [0.80, ∞) AND >= 80% of the pairs are inside. Returns the
    floor dict, or None when the set is out of scope."""
    if entry.get("budgeted") or entry.get("class") != "P-4K":
        return None
    if entry.get("obs_a") != "D" or \
            entry.get("obs_b") not in ("C", "M"):
        return None
    med = kstats.median(list(ratios_t))
    frac = sum(1 for ratio in ratios_t
               if ratio >= M1_FLOOR_4K) / len(ratios_t)
    return {"threshold": M1_FLOOR_4K, "median": med,
            "frac_inside": frac,
            "holds": med >= M1_FLOOR_4K and frac >= 0.8}


def judge_m1_set(set_id: str, entry: dict, cell_verdicts: list,
                 manifest: dict) -> dict:
    """Combine an M1 set's cells into the set verdict (ADR-0016: the
    set's own pair/attempt counts; the attempt budget is ENFORCED (an
    exhausted budget is INVALID, never PASS); the frozen median+80%
    rule decides budgeted sets, others publish ENVELOPE medians)."""
    out: dict = {"set": set_id, "class": entry["class"],
                 "mode": f"{entry['obs_a']}/{entry['mode_a']} "
                         f"vs {entry['obs_b']}/{entry['mode_b']}",
                 "kernel": entry["kernel"], "budgeted": entry["budgeted"],
                 "kind": "m1-pairs", "workload": entry["workload"]}
    for verdict in cell_verdicts:
        if verdict.get("errors"):
            out.update(verdict="INVALID",
                       reasons=[f"{verdict['cell']}: {verdict['errors']}"])
            return out
    audit_reasons = audit_m1_attempt_ids(cell_verdicts)
    if audit_reasons:
        out.update(verdict="INVALID", reasons=audit_reasons)
        return out
    pairs = form_pairs(cell_verdicts)
    out["pairs"] = pairs
    valid_pairs = sorted((pair for pair in pairs if pair["valid"]),
                         key=lambda pair: pair["pair"])
    valid = len(valid_pairs)
    attempted = len(pairs)
    out["set_check"] = {"qualified": valid >= entry["pairs"],
                        "valid_pairs": valid,
                        "attempted_pairs": attempted}
    if attempted > entry["max_attempted"]:
        out.update(verdict="INVALID",
                   reasons=[f"attempt budget exhausted: {attempted}/"
                            f"{entry['max_attempted']} attempted"])
        return out
    if valid < entry["pairs"]:
        out.update(verdict="INVALID",
                   reasons=[f"only {valid}/{entry['pairs']} valid pairs"])
        return out
    if entry["budgeted"]:
        # F2 (codex review) + A3: when spares push the valid count
        # past the quorum, the frozen 80% rule is undefined (8/10 vs
        # 9/11) and spare substitution can unbalance the AB/BA order
        # (the frozen gate pins each pair's parity, not the aggregate
        # 5/5). Decide on the first `pairs` valid pairs in attempt
        # order (pair names are zero-padded attempt indices); extras
        # stay published but non-deciding. The 5/5 order balance is
        # REQUIRED for a budgeted verdict (ADR-0016 counterfactual
        # discipline); anything else is INVALID, never a quiet PASS.
        deciding = valid_pairs[:entry["pairs"]]
        out["deciding_pairs"] = [pair["pair"] for pair in deciding]
        out["non_deciding_pairs"] = [pair["pair"] for pair in
                                     valid_pairs[entry["pairs"]:]]
        firsts = [pair["order"][0] for pair in deciding]
        first_a = sum(1 for side in firsts if side == "A")
        out["order_balance"] = {"first_a": first_a,
                                "first_b": len(firsts) - first_a}
        if first_a * 2 != len(firsts):
            out.update(verdict="INVALID",
                       reasons=[f"order balance {first_a}/"
                                f"{len(firsts) - first_a} over deciding "
                                "pairs, want 5/5"])
            return out
        ratios_t = [pair["ratios"]["throughput"] for pair in deciding]
        ratios_p99 = [pair["ratios"]["p99"] for pair in deciding]
    else:
        ratios_t = [pair["ratios"]["throughput"] for pair in valid_pairs]
        ratios_p99 = [pair["ratios"]["p99"] for pair in valid_pairs]
    out["medians"] = {"throughput": kstats.median(ratios_t),
                      "p99": kstats.median(ratios_p99)}
    if entry["budgeted"]:
        budgets = manifest["budgets"]
        b1 = kstats.set_verdict(
            ratios_t, lo=budgets["B1_throughput_ratio_min"], hi=None)
        b2 = kstats.set_verdict(
            ratios_p99, lo=None, hi=budgets["B2_p99_ratio_max"])
        out["B1"] = b1
        out["B2"] = b2
        if b1 == "PASS" and b2 == "PASS":
            out.update(verdict="PASS", reasons=[])
        elif b1 == "FAIL" or b2 == "FAIL":
            out.update(verdict="FAIL",
                       reasons=[f"B1={b1} B2={b2}"])
        else:
            out.update(verdict="INCONCLUSIVE",
                       reasons=[f"B1={b1} B2={b2}"])
    else:
        out.update(verdict="ENVELOPE",
                   reasons=["non-budget set: envelope published"])
        floor = eval_m1_disabled_floor(entry, ratios_t)
        if floor is not None:
            out["floor"] = floor
    return out


def perturbation_report(cell_verdicts: list, bulk: list) -> dict:
    """Reference-perturbation control: ledger-vs-bulk throughput.

    Compares bulk-mode legs against the ledger legs on the same
    side. NOTE (P9R1A-N8): the sealed P9 campaign used the
    pre-fix fixture whose bulk legs skipped ledger rows but
    still read three timestamps per op — those ratios bound
    row-materialization cost only, not timestamping cost. The
    repaired fixture's roundtrip_bulk reads no timestamps (P9R2O-N6
    scope note: worker_loop still reads the clock once per op
    for pacing/phase, so the no-clock guarantee covers
    roundtrip_bulk only), so future bulk legs bound the
    driver-observation perturbation less that symmetric per-op
    clock read.
    """
    report: dict = {}
    for pair in bulk:
        if not pair["valid"]:
            report[pair["pair"]] = {"valid": False,
                                    "reasons": pair["reasons"]}
    ledger_thr: dict = {"A": [], "B": []}
    bulk_thr: dict = {}
    for verdict in cell_verdicts:
        for leg in verdict.get("legs", []):
            if not leg.get("valid") or "stats" not in leg:
                continue
            if leg.get("bulk"):
                bulk_thr[leg["side"]] = leg["stats"]["throughput"]
            else:
                ledger_thr[leg["side"]].append(
                    leg["stats"]["throughput"])
    for side in ("A", "B"):
        if side in bulk_thr and ledger_thr[side]:
            med = kstats.median(ledger_thr[side])
            report[f"bulk_vs_ledger_{side}"] = {
                "bulk_throughput": bulk_thr[side],
                "ledger_median_throughput": med,
                "ratio": bulk_thr[side] / med,
            }
    return report


def judge_m1_diag(diag_id: str, entry: dict, cell_verdict: dict) -> dict:
    """Adjudicate the m1-612-ctx diagnostic (F3 + A3).

    The diag's C leg is frozen-invalid BY DESIGN (aggregation mode +
    6.12-floor subject shape never satisfy ``check_leg_agg``), so the
    frozen legs-valid gate cannot adjudicate it. The PASS bar is: one
    B-side aggregation leg, a clean boot-quiet, a clean driver run, a
    clean capture (rc in {0, 3}), full attach (9/9 per the frozen
    attach audit), POSITIVE observation on the driver and both sensor
    ledgers with a bounded system/ops ratio, and the A2 ctx exactness
    rules. Driver/capture fields are re-derived from the judged leg —
    every early ``judge_leg`` exit (unreadable summary, driver
    failure, timing or thread mismatch, corrupt ledger) is a genuine
    evidence failure, never a shape artifact, so a missing field is
    INVALID. The frozen shape verdict is copied through for
    transparency.
    """
    out: dict = {"diag": diag_id, "kind": entry["kind"],
                 "kernel": entry["kernel"]}
    legs = cell_verdict.get("legs", [])
    if len(legs) != 1:
        out.update(verdict="INVALID",
                   reasons=[f"want exactly 1 leg, have {len(legs)}"])
        return out
    leg = legs[0]
    out["leg"] = {key: leg.get(key) for key in
                  ("leg_id", "valid", "outcome", "reasons", "stats",
                   "observer", "ctx")}
    out["leg"]["frozen_shape"] = {"valid": leg.get("valid"),
                                  "reasons": leg.get("reasons", [])}
    reasons = []
    if leg.get("side") != "B" or leg.get("mode") != "aggregation":
        reasons.append(f"want one B-side aggregation leg, have "
                       f"side={leg.get('side')} "
                       f"mode={leg.get('mode')}")
    if cell_verdict.get("spec_boot_invalid"):
        reasons.append("boot quiet failed")
    driver = leg.get("driver") or {}
    if leg.get("driver_rc") != 0 or driver.get("rc") != 0 or \
            leg.get("driver_timeout"):
        reasons.append(f"driver rc={driver.get('rc')} "
                       f"driver_rc={leg.get('driver_rc')} "
                       f"timeout={leg.get('driver_timeout')}")
    if leg.get("capture_rc") not in (0, 3):
        reasons.append(f"capture rc={leg.get('capture_rc')} (want 0/3)")
    diag = leg.get("diag") or {}
    for key in ("attach_error", "ctx_error", "report_error",
                "overflow_error"):
        if diag.get(key):
            reasons.append(f"diag {key}: {diag[key]}")
    attach = diag.get("attach") or {}
    out["attach"] = diag.get("attach")
    if attach.get("attached") != 9 or attach.get("expected") != 9:
        reasons.append(f"attach {attach.get('attached')}/"
                       f"{attach.get('expected')} (want 9/9)")
    out["ctx"] = diag.get("ctx")
    out["totals_calls"] = diag.get("totals_calls")
    # N2 (A3 review): the frozen driver<->sensor per-op reconciliation
    # does NOT run on the diag path (the frozen shape verdict is
    # ignored by design), so agreeing-but-empty (or grossly partial)
    # sensor ledgers would PASS on exactness alone. Require positive
    # observation on the driver and both sensors, plus a bounded
    # system/ops ratio. The band [1.5, 6.0] contains the flat shape
    # (7.x: 1595873/797936 = 2.00000125) and the floor shape (6.12.111
    # sealed diag: 4907528/1226880 = 4.0000065) with margin, and
    # excludes vacuous 0x, flat-missing-one-side 1x, and runaway >=6x
    # — without pinning an exact floor equation (A1 overclaim
    # discipline). Known residual: a floor leg missing one cryptd arm
    # (~2-3x) still passes the band; single-arm detection needs the
    # rows pin (sealed rows=12, N=1 — pin only after the re-stage
    # confirms stability).
    driver_ops = driver.get("ops_total")
    totals = diag.get("totals_calls")
    system = (diag.get("ctx") or {}).get("system_calls")
    if not _is_positive_int(driver_ops):
        reasons.append(f"observation: driver ops_total={driver_ops!r} "
                       "(want positive int)")
    elif not _is_positive_int(totals) or not _is_positive_int(system):
        reasons.append(f"observation: report totals={totals!r} "
                       f"ctx system={system!r} (want both positive)")
    else:
        ratio = system / driver_ops
        out["system_per_op"] = ratio
        if not 1.5 <= ratio <= 6.0:
            reasons.append(f"observation ratio system/ops={ratio:.4f} "
                           "(want within [1.5, 6.0])")
    for reason in diag.get("exactness") or []:
        reasons.append(f"exactness: {reason}")
    if reasons:
        out.update(verdict="INVALID", reasons=reasons)
        return out
    out.update(verdict="PASS",
               reasons=["6.12 floor: attach + exactness proven"])
    return out


def judge_diag(diag_id: str, cell_verdict: dict, manifest: dict) -> dict:
    entry = find_diag(manifest, diag_id)
    out: dict = {"diag": diag_id, "kind": entry["kind"],
                 "kernel": entry["kernel"]}
    if cell_verdict.get("errors"):
        out.update(verdict="INVALID",
                   reasons=cell_verdict["errors"])
        return out
    if entry["kind"] == "m1-612-ctx":
        # F3: above the frozen legs-valid gate — the diag's C leg is
        # frozen-invalid by design; judge_m1_diag adjudicates it.
        return judge_m1_diag(diag_id, entry, cell_verdict)
    if not all(leg["valid"] for leg in cell_verdict.get("legs", [])):
        bad = [leg["leg_id"] for leg in cell_verdict.get("legs", [])
               if not leg["valid"]]
        out.update(verdict="INVALID", reasons=[f"legs invalid: {bad}"])
        return out
    if entry["kind"] == "footprint":
        leg = cell_verdict["legs"][0]
        out["footprint"] = {"totals": leg.get("totals"),
                            "observer": leg.get("observer")}
        out.update(verdict="ENVELOPE", reasons=["footprint published"])
        return out
    pairs = form_pairs([cell_verdict])
    out["pairs"] = pairs
    out.update(verdict="ENVELOPE", reasons=["probe published"])
    return out


def cmd_verify(args) -> int:
    # P9R1O-N9: judging must not rewrite sealed evidence. The
    # verdicts go to --out-dir; the legacy in-place path needs
    # an explicit --in-place flag, and contradictory custody
    # flags fail closed.
    if args.out_dir is not None and args.in_place:
        print("verify: pass exactly one of --out-dir / --in-place",
              file=sys.stderr)
        return 2
    if args.out_dir is None and not args.in_place:
        print("verify: refusing implicit in-place judging inside "
              "sealed evidence; pass --out-dir <dir> (or --in-place "
              "for the legacy path)", file=sys.stderr)
        return 2
    if args.out_dir is not None:
        # P9R2O-N6: an --out-dir inside --evidence-dir would
        # write judgments into the sealed tree (and the next
        # run would judge its own output as a cell). Fail
        # closed instead of warning.
        out_abs = os.path.realpath(args.out_dir)
        ev_abs = os.path.realpath(args.evidence_dir)
        if out_abs == ev_abs or out_abs.startswith(ev_abs + os.sep):
            print("verify: refusing --out-dir inside --evidence-dir "
                  "(judgments must not land in sealed evidence)",
                  file=sys.stderr)
            return 2
    out_root = Path(args.out_dir) if args.out_dir else None
    manifest = load_any_manifest(Path(args.manifest))
    cells_dir = Path(args.evidence_dir)
    required_sets = [entry["id"] for entry in manifest["sets"]]
    required_diags = [entry["id"] for entry in manifest["diagnostics"]]
    errors: list = []
    set_cells: dict = {}
    verdicts_dir = (out_root if out_root else cells_dir) / "verdicts"
    verdicts_dir.mkdir(parents=True, exist_ok=True)
    if out_root is None:
        print("verify: WARNING: judging in place inside sealed "
              "evidence (--in-place); prefer --out-dir",
              file=sys.stderr)
    for cell in sorted(cells_dir.iterdir()):
        if not cell.is_dir() or cell.name == "verdicts":
            continue
        verdict = verify_cell(cell, manifest)
        krecept.atomic_write_json(verdicts_dir / f"{cell.name}.json",
                                  {"cell": verdict})
        if verdict.get("errors"):
            errors.append(f"{cell.name}: {verdict['errors']}")
        stage = verdict.get("stage", {})
        if stage.get("kind") == "set" and stage.get("set"):
            set_cells.setdefault(stage["set"], []).append(verdict)
        elif stage.get("kind") == "diag" and stage.get("diag"):
            set_cells.setdefault(stage["diag"], []).append(verdict)
    campaign: dict = {"sets": {}, "diags": {}}
    for set_id in required_sets:
        cells = set_cells.get(set_id, [])
        if not cells:
            errors.append(f"missing mandatory set cell {set_id}")
            campaign["sets"][set_id] = {"set": set_id, "verdict": "MISSING"}
            continue
        judged = judge_set(set_id, cells, manifest)
        campaign["sets"][set_id] = judged
        print(f"{set_id}: {judged['verdict']} "
              f"{' '.join(judged.get('reasons', []))}")
        if judged["verdict"] == "INVALID":
            errors.append(f"{set_id}: INVALID "
                          f"{' '.join(judged.get('reasons', []))}")
    for diag_id in required_diags:
        cells = set_cells.get(diag_id, [])
        if not cells:
            errors.append(f"missing mandatory diagnostic cell {diag_id}")
            campaign["diags"][diag_id] = {"diag": diag_id,
                                          "verdict": "MISSING"}
            continue
        judged = judge_diag(diag_id, cells[0], manifest)
        campaign["diags"][diag_id] = judged
        print(f"{diag_id}: {judged['verdict']} "
              f"{' '.join(judged.get('reasons', []))}")
        if judged["verdict"] == "INVALID":
            errors.append(f"{diag_id}: INVALID "
                          f"{' '.join(judged.get('reasons', []))}")
    present = [cell.name for cell in sorted(cells_dir.iterdir())
               if cell.is_dir() and cell.name != "verdicts"]
    locks = _CLI.verify_campaign_locks(cells_dir, present)
    campaign["locks"] = locks
    print(f"locks: {locks['verdict']} common={locks['common']}")
    if locks["verdict"] != "PASS":
        errors.extend(locks["reasons"])
    krecept.atomic_write_json(
        (out_root if out_root else cells_dir) / "campaign.json", campaign)
    print(f"verdicts: {verdicts_dir}")
    buds = {set_id: (judged.get("B1"), judged.get("B2"))
            for set_id, judged in campaign["sets"].items()
            if judged.get("budgeted")}
    print(f"budgets: {buds}")
    if errors:
        print(f"campaign: INVALID ({len(errors)} errors)")
        for err in errors[:20]:
            print(f"  - {err}")
        return 1
    print("campaign: JUDGED (all mandatory cells judged, seals+locks ok)")
    return 0


def cmd_analyze(args) -> int:
    cells_dir = Path(args.evidence_dir)
    campaign_path = Path(args.campaign) if args.campaign \
        else cells_dir / "campaign.json"
    try:
        campaign = json.loads(campaign_path.read_text())
    except (OSError, ValueError) as err:
        print(f"analyze: {campaign_path} unreadable: {err}")
        return 2
    lines = ["# T14 P9 performance campaign report",
             "",
             "Budgets (frozen, docs/bench-thresholds.md): B1 throughput "
             "ratio >= 0.95, B2 workload-p99 ratio <= 1.10 on qualified "
             "4 KiB / 1 MiB aggregate sets.",
             "",
             "## Pair-sets",
             "",
             "| Set | Class x Mode x Kernel | Pairs | Median thr | "
             "Median p99 | Verdict |",
             "|---|---|---|---|---|---|"]
    for set_id in sorted(campaign.get("sets", {})):
        judged = campaign["sets"][set_id]
        meds = judged.get("medians", {})
        check = judged.get("set_check", {})
        lines.append(
            f"| {set_id} | {judged.get('class')} x {judged.get('mode')} x "
            f"{judged.get('kernel')} | {check.get('valid_pairs')}/"
            f"{check.get('attempted_pairs')} | "
            f"{meds.get('throughput')} | {meds.get('p99')} | "
            f"{judged.get('verdict')} |")
    lines += ["", "## Diagnostics", ""]
    for diag_id in sorted(campaign.get("diags", {})):
        judged = campaign["diags"][diag_id]
        lines.append(f"- {diag_id} ({judged.get('kind')}): "
                     f"{judged.get('verdict')}")
    lines += ["", "## Notes", "",
              "- Ratios are B/A per pair in preserved run order; "
              "medians over valid pairs only.",
              "- ENVELOPE sets publish operating data without a budget "
              "verdict; see per-cell verdicts.json for legs, observer "
              "metrics, and loss dimensions.",
              ""]
    report = "\n".join(lines)
    if args.out:
        Path(args.out).write_text(report)
        print(f"wrote {args.out}")
    else:
        print(report)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kcrypto-perf.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    plan = sub.add_parser("plan", help="list frozen sets/diagnostics")
    plan.add_argument("--manifest", default=str(PERF_MANIFEST))
    run = sub.add_parser("run", help="run one set/diagnostic cell")
    run.add_argument("--manifest", default=str(PERF_MANIFEST))
    group = run.add_mutually_exclusive_group(required=True)
    group.add_argument("--set")
    group.add_argument("--diag")
    run.add_argument("--kryprobe", default=None,
                     help="frozen manifest: observer binary (M1: use --obs-a/--obs-b)")
    run.add_argument("--bpf-dir", default=None,
                     help="frozen manifest: BPF object dir (M1: use --obs-a/--obs-b)")
    run.add_argument("--obs-a", default=None,
                     help="M1 manifest: side-A observer DISABLED or CLI:BPFDIR")
    run.add_argument("--obs-b", default=None,
                     help="M1 manifest: side-B observer DISABLED or CLI:BPFDIR")
    run.add_argument("--metadata", default=None,
                     help="M1 manifest: frozen metadata file "
                     "(required iff a staged side has role M)")
    run.add_argument("--ko", action="append", default=[],
                     help="K=V fixture module, repeatable")
    run.add_argument("--driver", required=True)
    run.add_argument("--out-root", required=True)
    run.add_argument("--evidence-dir", required=True)
    run.add_argument("--lock", action="append", required=True,
                     help="repeat: shared BPF lock + task bench lock")
    run.add_argument("--spare", type=int, default=0)
    run.add_argument("--start-pair", type=int, default=0)
    run.add_argument("--pairs", type=int, default=None)
    verify = sub.add_parser("verify", help="judge sealed cells")
    verify.add_argument("--manifest", default=str(PERF_MANIFEST))
    verify.add_argument("--evidence-dir", required=True)
    verify.add_argument("--out-dir", default=None,
                        help="write verdicts/ + campaign.json here "
                        "(never inside --evidence-dir)")
    verify.add_argument("--in-place", action="store_true",
                        help="legacy: write verdicts/ + campaign.json "
                        "inside --evidence-dir (disturbs seals)")
    analyze = sub.add_parser("analyze", help="campaign report")
    analyze.add_argument("--evidence-dir", required=True)
    analyze.add_argument("--campaign", default=None,
                         help="campaign.json to report (default: "
                         "<evidence-dir>/campaign.json)")
    analyze.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    if args.cmd == "plan":
        return cmd_plan(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "analyze":
        return cmd_analyze(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
