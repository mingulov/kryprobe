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

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_campaign_cli", str(HERE / "kcrypto-campaign.py"))
_CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLI)

SCENARIOS = HERE / "kcrypto_perf" / "scenarios"
PERF_MANIFEST = HERE.parent / "tests" / "kcrypto_perf" / "cells.json"


def sha256_file(path: Path) -> str:
    return krecept.sha256_file(Path(path))


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


def _gen_diag_legs(entry: dict, paced_rate: int) -> list:
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
    manifest = kmanifest.load_manifest(Path(args.manifest))
    print(f"manifest {args.manifest} sha={manifest['_manifest_sha256'][:12]}...")
    total_legs = 0
    for entry in manifest["sets"]:
        legs = gen_legs(entry, manifest, "set")
        total_legs += len(legs)
        print(f"set {entry['id']}: {entry['class']} x {entry['mode']} x "
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
        "scenario": "perf_set.sh", "fixture": "kcrypto_perf.py",
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
    manifest = kmanifest.load_manifest(Path(args.manifest))
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
    print(f"staged {run_dir} pins={stage['sha256']['kryprobe'][:12]}... "
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
    for sub in ("legs", "kryprobe-bpf", "judge"):
        src = run_dir / sub
        if src.is_dir():
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
              windows: tuple) -> dict:
    """Judge one staged leg from sealed files (stats + validity).

    ``windows`` is the frozen (warmup_s, measure_s) pair from the
    bound manifest; driver timing must match it (P9R1A-N7).
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
        return judge_observed_leg(cell_dir, leg, kernel, summary, out)
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
    return judge_observed_leg(cell_dir, leg, kernel, summary, out)


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


def observer_metrics(cell_dir: Path, leg: dict, parsed_agg,
                     parsed_lc) -> dict:
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
    if parsed_agg is not None:
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


def judge_observed_leg(cell_dir: Path, leg: dict, kernel: str,
                       summary: dict, out: dict) -> dict:
    legs_dir = cell_dir / "legs"
    leg_id = leg["leg_id"]
    capture_rc = _read_int_kv(legs_dir / f"{leg_id}-capture-rc.txt",
                              "capture_rc")
    out["capture_rc"] = capture_rc
    if leg["mode"] == "aggregation":
        try:
            parsed = kparsers.parse_api_returns(
                legs_dir / f"{leg_id}-report.json")
        except kparsers.ParseError as err:
            out.update(valid=False, reasons=[str(err)], outcome="invalid")
            return out
        threads = leg.get("threads", 1)
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
    pin_reasons, pin_obs = check_stage_pins(cell_dir, stage)
    verdict["pin_check"] = pin_obs
    if pin_reasons:
        verdict["errors"].extend(pin_reasons)
        return verdict
    kernel = stage.get("kernel")
    try:
        quiet = kparsers.parse_api_returns(cell_dir / "quiet-report.json")
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
    legs = []
    for idx, leg in enumerate(spec):
        judged = judge_leg(cell_dir, leg, kernel, windows)
        judged["order"] = idx
        if not quiet_check["valid"]:
            judged["valid"] = False
            judged["outcome"] = "invalid"
            judged["reasons"] = (judged.get("reasons", []) +
                                 ["boot quiet failed"])
        legs.append(judged)
    verdict["legs"] = legs
    return verdict


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


def judge_diag(diag_id: str, cell_verdict: dict, manifest: dict) -> dict:
    entry = find_diag(manifest, diag_id)
    out: dict = {"diag": diag_id, "kind": entry["kind"],
                 "kernel": entry["kernel"]}
    if cell_verdict.get("errors"):
        out.update(verdict="INVALID",
                   reasons=cell_verdict["errors"])
        return out
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
    manifest = kmanifest.load_manifest(Path(args.manifest))
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
    run.add_argument("--kryprobe", required=True)
    run.add_argument("--bpf-dir", required=True)
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
