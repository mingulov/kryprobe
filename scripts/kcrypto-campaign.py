#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""kcrypto-campaign: thin plan/run/verify CLI for the T13 consumer campaign.

Usage (from the product worktree):

  scripts/kcrypto-campaign.py plan --manifest tests/kcrypto_campaign/cells.json
  scripts/kcrypto-campaign.py run --manifest ... --portion R02-7014 \\
      --kryprobe <bin> --bpf-dir <dir> --ko 7.0.14=<ko> --fixture <gen> \\
      --out-root <dir> --lock <file> --evidence-dir <dir>
  scripts/kcrypto-campaign.py verify --manifest ... --cells-dir <dir>

``plan`` lists the runnable portions. ``run`` stages ONE portion
(fresh run dir, explicit artifact paths — never ambient files),
boots the owned guest, collects the cell, validates R01-det
ledgers on the host, and seals the cell into the evidence dir
with its host receipt. ``verify`` is offline: it reads the
manifest + sealed cells, runs the oracle predicates, reconciles
every receipt, and prints verdicts — it never launches work,
never rewrites inputs, and never repairs a run.

Every path is explicit: the campaign takes the fixture path, the
CLI/BPF/module paths and the oracle (this package) as arguments
or manifest pins. ``--ko`` is required only for portions whose
scenario stages a fixture module (r01_det); other scenarios
record ``module_sha=none`` in both identity files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from kcrypto_campaign import identity as kidentity  # noqa: E402
from kcrypto_campaign import inputs as kinputs  # noqa: E402
from kcrypto_campaign import oracles  # noqa: E402
from kcrypto_campaign import owned_guest  # noqa: E402
from kcrypto_campaign import receipt as kreceipt  # noqa: E402
from kcrypto_campaign import reconcile  # noqa: E402

SCENARIOS = HERE / "kcrypto_campaign" / "scenarios"

# Scenario -> files the guest must produce (besides the common
# identity/environment/cleanup/done set). A missing file fails
# the terminal-flush gate: the run never seals short.
EXPECTED_FILES = {
    "r01_det.sh": ["ledger-legA.jsonl", "ledger-legB.jsonl",
                   "report-legA.json", "report-legB.json",
                   "capture-legA.stderr.log", "capture-legB.stderr.log"],
    "r01_floor.sh": ["workload-stdout.log", "workload-rc.txt",
                     "aggregate.json", "aggregate.stderr.log",
                     "kernel-ref.json",
                     "refusal-rc.txt", "refusal-stderr.log"],
    "r02_dmcrypt.sh": ["workload.json", "kernel-ref.json",
                       "product-write.json", "product-read.json",
                       "product-quiet-before.json", "product-quiet-after.json",
                       "capture-product-write.stderr.log",
                       "capture-product-read.stderr.log",
                       "capture-product-quiet-before.stderr.log",
                       "capture-product-quiet-after.stderr.log"],
    "r03_xfrm.sh": ["ledger-a.json", "ledger-b.json", "authfail-ledger.json",
                    "kernel-ref.json",
                    "product-main.json", "product-authfail.json",
                    "product-quiet-before.json", "product-quiet-after.json",
                    "capture-product-main.stderr.log",
                    "capture-product-authfail.stderr.log",
                    "capture-product-quiet-before.stderr.log",
                    "capture-product-quiet-after.stderr.log",
                    "xfrm-state-count.txt"],
    "r04_deny.sh": ["refusal-rc.txt", "refusal-stderr.log",
                    "control-stdout.log", "control-rc.txt",
                    "control.json", "control.stderr.log",
                    "kernel-ref.json"],
    "r04_foreign.sh": ["owned-pids.json", "foreign-pids.json",
                       "owned-stdout.log", "foreign-stdout.log",
                       "product.json", "capture.stderr.log"],
}

COMMON_FILES = ["environment.txt", "identity-before.env", "identity-after.env",
                "btf-objs.txt", "dmesg-tail.txt", "cleanup.txt", "done.txt"]

# Body inventory per scenario (required/actual comparison).
SCENARIO_BODIES = {
    "r01_det.sh": ["leg-a", "leg-b"],
    "r01_floor.sh": ["aggregate", "refusal"],
    "r02_dmcrypt.sh": ["quiet-before", "write", "read", "wrongkey", "quiet-after"],
    "r03_xfrm.sh": ["quiet-before", "main", "authfail", "quiet-after"],
    "r04_deny.sh": ["refusal", "control"],
    "r04_foreign.sh": ["owned", "foreign"],
}

# Guest-side helper drivers staged per scenario.
SCENARIO_HELPERS = {
    "r01_det.sh": [],
    "r01_floor.sh": ["ftrace_ref.sh"],
    "r02_dmcrypt.sh": ["ftrace_ref.sh", "r02_io.py"],
    "r03_xfrm.sh": ["ftrace_ref.sh", "r03_traffic.py"],
    "r04_deny.sh": ["ftrace_ref.sh"],
    "r04_foreign.sh": [],
}

# Key-material scan patterns (verify gate): XTS/dm keys are 100+
# hex runs; `ip xfrm` keys spell `0x` + 32+ hex. Commit hashes
# (40 hex) and sha256 (64 hex) never match either pattern.
KEY_PATTERNS = [re.compile(r"[0-9a-f]{100,}"), re.compile(r"0x[0-9a-f]{32,}")]

AGG_OK = "ok"

# Cross-portion artifacts that must be byte-identical in every
# sealed cell (campaign pin-uniformity gate). Per-portion
# artifacts (guest-config, kcrypto_fixture.ko, inner.sh, helpers)
# are pinned within each cell instead.
UNIFORM_PINS = ["kryprobe", "kryprobe-bpf/kcrypto.bpf.o",
                "kryprobe-bpf/kcrypto-lifecycle.bpf.o",
                "kcrypto_gen.py", "oracles.py"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_portion(manifest: dict, portion_id: str) -> tuple[dict, dict]:
    for cell in manifest["cells"]:
        for portion in cell["portions"]:
            if portion["id"] == portion_id:
                return cell, portion
    raise kinputs.InputError(f"unknown portion {portion_id!r}")


def cmd_plan(args) -> int:
    manifest = kinputs.load_inputs(Path(args.manifest))
    print(f"manifest: {args.manifest}")
    print(f"sha256: {manifest['_manifest_sha256']}")
    for cell in kinputs.t13_cells(manifest):
        for portion in cell["portions"]:
            bounds = portion["bounds"]
            print(f"{portion['id']} kernel={portion['kernel']} "
                  f"profile={portion['profile']} "
                  f"scenario={portion['stimulus']['scenario']} "
                  f"timeout_s={bounds.get('timeout_s')}")
    return 0


def stage_run_dir(args, portion: dict, manifest_sha: str, vng: str) -> tuple[Path, dict]:
    out_root = Path(args.out_root)
    out_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_dir = out_root / args.portion
    if run_dir.exists():
        raise owned_guest.GuestError(
            f"run dir {run_dir} already exists (refusing reuse)")
    run_dir.mkdir(mode=0o700)
    kernel = portion["kernel"]
    scenario = portion["stimulus"]["scenario"]
    if scenario not in EXPECTED_FILES:
        raise kinputs.InputError(f"portion {args.portion} names unknown scenario {scenario!r}")
    ko_map = {}
    for item in args.ko or []:
        key, _, val = item.partition("=")
        if not key or not val:
            raise ValueError(f"bad --ko {item!r}, want K=V")
        ko_map[key] = val
    pins: dict[str, str] = {}
    kryprobe = Path(args.kryprobe).resolve(strict=True)
    shutil.copyfile(kryprobe, run_dir / "kryprobe")
    (run_dir / "kryprobe").chmod(0o755)
    pins["kryprobe"] = sha256_file(run_dir / "kryprobe")
    bpf_dir = Path(args.bpf_dir).resolve(strict=True)
    (run_dir / "kryprobe-bpf").mkdir()
    for obj in ("kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o"):
        shutil.copyfile(bpf_dir / obj, run_dir / "kryprobe-bpf" / obj)
        pins[f"kryprobe-bpf/{obj}"] = sha256_file(run_dir / "kryprobe-bpf" / obj)
    fixture = Path(args.fixture).resolve(strict=True)
    shutil.copyfile(fixture, run_dir / "kcrypto_gen.py")
    pins["kcrypto_gen.py"] = sha256_file(run_dir / "kcrypto_gen.py")
    configs = sorted(Path(f"~/.cache/virtme-ng/{vng}/amd64/boot").expanduser()
                     .glob("config-*"))
    if len(configs) != 1:
        raise ValueError(f"want exactly one guest config for {vng}, found {configs}")
    shutil.copyfile(configs[0], run_dir / "guest-config")
    pins["guest-config"] = sha256_file(run_dir / "guest-config")
    if scenario == "r01_det.sh":
        if kernel not in ko_map:
            raise ValueError(f"scenario {scenario} needs --ko for {kernel}")
        ko_src = Path(ko_map[kernel]).resolve(strict=True)
        shutil.copyfile(ko_src, run_dir / "kcrypto_fixture.ko")
        pins["kcrypto_fixture.ko"] = sha256_file(run_dir / "kcrypto_fixture.ko")
    else:
        pins["kcrypto_fixture.ko"] = "none"
    inner_src = SCENARIOS / scenario
    shutil.copyfile(inner_src, run_dir / "inner.sh")
    pins["inner.sh"] = sha256_file(run_dir / "inner.sh")
    for helper in SCENARIO_HELPERS[scenario]:
        shutil.copyfile(SCENARIOS / helper, run_dir / helper)
        pins[helper] = sha256_file(run_dir / helper)
    oracle_src = HERE / "kcrypto_campaign" / "oracles.py"
    shutil.copyfile(oracle_src, run_dir / "oracles.py")
    pins["oracles.py"] = sha256_file(run_dir / "oracles.py")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE.parent,
                          capture_output=True, text=True, check=True).stdout.strip()
    (run_dir / "head-sha.txt").write_text(head + "\n")
    pins["head-sha.txt"] = sha256_file(run_dir / "head-sha.txt")
    stage = {"schema": "kcrypto-t13-stage/v1", "portion": args.portion,
             "kernel": kernel, "head": head, "manifest_sha256": manifest_sha,
             "sha256": pins}
    (run_dir / "stage.json").write_text(json.dumps(stage, indent=2) + "\n")
    (run_dir / "pins.env").write_text(
        f"ORACLE_SHA={pins['oracles.py']}\nCLI_SHA={pins['kryprobe']}\n"
        f"BPF_AGG_SHA={pins['kryprobe-bpf/kcrypto.bpf.o']}\n"
        f"BPF_LC_SHA={pins['kryprobe-bpf/kcrypto-lifecycle.bpf.o']}\n"
        f"MODULE_SHA={pins['kcrypto_fixture.ko']}\n"
        f"FIXTURE_SHA={pins['kcrypto_gen.py']}\n"
        f"PORTION={args.portion}\n")
    return run_dir, stage


def validate_r01_ledger(worktree: Path, ledger: Path, run_id: str,
                        scenario: str, suffix: str) -> dict:
    """Host-side strict ledger validation (run step, recorded fact).

    Shells the committed testkit ``guest_ledger`` body (the same
    strict parser the fixture protocol requires) with the ledger
    pulled from the guest. A nonzero rc fails the cell.
    """
    cargo = shlex.split(os.environ.get("CARGO_TEST_CMD", "cargo test --locked"))
    env = dict(os.environ, KCRYPTO_LEDGER_PATH=str(ledger),
               KCRYPTO_RUN_ID=run_id, KCRYPTO_SCENARIO=scenario,
               KCRYPTO_SUFFIX=suffix)
    test_cmd = cargo + ["-p", "kryprobe-testkit", "--test", "guest_ledger",
                        "--", "--ignored"]
    proc = subprocess.run(test_cmd, cwd=worktree, env=env,
                          capture_output=True, text=True)
    tail = "\n".join(proc.stdout.splitlines()[-3:]) if proc.stdout else proc.stderr[-300:]
    return {"rc": proc.returncode, "tail": tail}


def ledger_semantics(ledger_path: Path) -> dict:
    """Semantic digest of a fixture ledger: row counts by phase + op.

    Timestamps/run-ids/sequence numbers are excluded (they differ
    across legs by design); every semantic count must match
    exactly across determinism legs.
    """
    phases: dict[str, int] = {}
    total = 0
    for line in Path(ledger_path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        total += 1
        key = f"{row.get('phase')}/{row.get('op')}/{row.get('result', '')}"
        phases[key] = phases.get(key, 0) + 1
    return {"rows": total, "phases": phases}


def agg_entries(parsed: dict, family: str, op: str, result: str = AGG_OK) -> list:
    """All agg rows sharing (family, op, result) across algorithms/drivers."""
    return [entry for key, entry in parsed["agg"].items()
            if key[0] == family and key[1] == op and key[2] == result]


def agg_calls(parsed: dict, family: str, op: str, result: str = AGG_OK) -> int:
    entries = agg_entries(parsed, family, op, result)
    if not entries:
        raise oracles.OracleError(
            f"report has no agg row ({family}, {op}, {result})")
    return sum(entry["calls"] for entry in entries)


def agg_bytes(parsed: dict, family: str, op: str, result: str = AGG_OK) -> int:
    entries = agg_entries(parsed, family, op, result)
    if not entries:
        raise oracles.OracleError(
            f"report has no agg row ({family}, {op}, {result})")
    return sum(entry["bytes"] for entry in entries)


def key_leak_scan(cell_dir: Path) -> list[str]:
    """Scan cell text files for key-material patterns (privacy gate)."""
    hits = []
    for path in sorted(cell_dir.iterdir()):
        if not path.is_file() or path.suffix not in (
                ".log", ".json", ".txt", ".env", ".sh", ".py"):
            continue
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for pattern in KEY_PATTERNS:
            if pattern.search(text):
                hits.append(f"{path.name}: {pattern.pattern}")
    return hits


def cmd_run(args) -> int:
    manifest = kinputs.load_inputs(Path(args.manifest))
    cell, portion = find_portion(manifest, args.portion)
    if portion["status"] != "T13" or cell["status"] != "T13":
        print(f"portion {args.portion} is not T13 runnable")
        return 2
    worktree = HERE.parent
    vng = manifest["global"]["vng"][portion["kernel"]]
    run_dir, stage = stage_run_dir(args, portion, manifest["_manifest_sha256"], vng)
    inner = str(run_dir / "inner.sh")
    name = f"t13-{args.portion}"
    locks = [Path(args.lock).resolve()] if isinstance(args.lock, str) else [
        Path(p).resolve() for p in args.lock]
    print(f"staged {run_dir} pins={stage['sha256']['kryprobe'][:12]}...")
    result = owned_guest.run_cell(
        portion_id=args.portion,
        vng_cmd=["vng", "--run", vng, "--user", "root", "--name", name,
                 "--cpus", "4", "--memory", "4G", "--cwd", "/",
                 "--rwdir", str(run_dir),
                 "--exec", f"sh {inner} {run_dir}"],
        run_dir=run_dir,
        name=name,
        lock_paths=locks,
        timeout_s=portion["bounds"]["timeout_s"],
    )
    print(f"wait={result['wait']} reaped={result['stop']['reaped']}")
    scenario = portion["stimulus"]["scenario"]
    validation: dict[str, dict] = {}
    if scenario == "r01_det.sh":
        for leg, run_id in (("legA", "t13r01a"), ("legB", "t13r01b")):
            ledger = run_dir / f"ledger-{leg}.jsonl"
            if ledger.is_file():
                validation[leg] = validate_r01_ledger(
                    worktree, ledger, run_id, "sync-once", args.portion)
                print(f"validate {leg}: rc={validation[leg]['rc']}")
            else:
                validation[leg] = {"rc": 127, "tail": "ledger file missing"}
        (run_dir / "validation.json").write_text(json.dumps(validation, indent=2))
    receipt = build_host_receipt(args, portion, manifest, run_dir, stage,
                                 result, validation)
    kreceipt.atomic_write_json(run_dir / "host-receipt.json", receipt)
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    cell_dir = evidence_dir / args.portion
    if cell_dir.exists():
        raise owned_guest.GuestError(
            f"evidence cell {cell_dir} already exists (refusing overwrite)")
    cell_dir.mkdir()
    for path in sorted(run_dir.iterdir()):
        if path.is_file():
            shutil.copyfile(path, cell_dir / path.name)
    for path in sorted((run_dir / "kryprobe-bpf").iterdir()):
        (cell_dir / "kryprobe-bpf").mkdir(exist_ok=True)
        shutil.copyfile(path, cell_dir / "kryprobe-bpf" / path.name)
    seal_names = sorted(p.name for p in cell_dir.iterdir() if p.is_file())
    seal_names += sorted(f"kryprobe-bpf/{p.name}"
                         for p in (cell_dir / "kryprobe-bpf").iterdir())
    kreceipt.seal_artifacts(cell_dir, seal_names, writers_done=True)
    print(f"sealed {cell_dir}")
    return 0


# Guest-side cleanup markers (cleanup.txt NAME=1 lines) required
# per scenario; "guest" (host-side reap) is always required.
SCENARIO_CLEANUP = {
    "r01_det.sh": ["module"],
    "r01_floor.sh": ["tracer"],
    "r02_dmcrypt.sh": ["tracer", "mapping", "loop", "keyfile"],
    "r03_xfrm.sh": ["tracer", "namespaces", "xfrm"],
    "r04_deny.sh": ["tracer"],
    "r04_foreign.sh": [],
}


def parse_cleanup_markers(run_dir: Path) -> list[str]:
    done = []
    try:
        for line in (run_dir / "cleanup.txt").read_text().splitlines():
            name, sep, value = line.partition("=")
            if sep and value.strip() == "1":
                done.append(name.strip())
    except OSError:
        pass
    return done


def build_host_receipt(args, portion: dict, manifest: dict, run_dir: Path,
                       stage: dict, result: dict, validation: dict) -> dict:
    """Assemble the run-step facts (verify adds oracle judgment)."""
    scenario = portion["stimulus"]["scenario"]
    expected = EXPECTED_FILES[scenario] + COMMON_FILES
    if scenario == "r01_det.sh":
        expected = expected + ["validation.json"]
    missing = [name for name in expected if not (run_dir / name).is_file()]
    done_ok = (run_dir / "done.txt").is_file() and "step=done" in (
        run_dir / "done.txt").read_text()
    try:
        before = kidentity.parse_identity_env(
            (run_dir / "identity-before.env").read_text())
        after = kidentity.parse_identity_env(
            (run_dir / "identity-after.env").read_text())
        id_verdict = kidentity.compare_identities(before, after)
    except (OSError, kidentity.IdentityError) as err:
        before, after = {}, {}
        id_verdict = {"stable": False, "mismatches": [],
                      "missing": [f"identity unreadable: {err}"]}
    staged = stage["sha256"]
    executed = dict(staged)
    hashes_unchanged = True
    for name, pinned in staged.items():
        if pinned == "none":
            continue
        target = run_dir / name
        try:
            if sha256_file(target) != pinned:
                hashes_unchanged = False
        except OSError:
            hashes_unchanged = False
    stop = result["stop"]
    wait = result["wait"]
    bodies = SCENARIO_BODIES[scenario]
    actual_bodies = [b for b in bodies if body_files_present(scenario, b, run_dir)]
    cleanup_required = ["guest"] + SCENARIO_CLEANUP[scenario]
    cleanup_done = (["guest"] if stop["reaped"] else []) + parse_cleanup_markers(run_dir)
    return {
        "schema": "kryprobe-consumer-receipt/v1",
        "cell_id": portion["id"].rsplit("-", 1)[0],
        "portion_id": portion["id"],
        "kernel": portion["kernel"],
        "profile": portion["profile"],
        "scenario": scenario,
        "manifest_sha256": manifest["_manifest_sha256"],
        "identity": {"before": before, "after": after, **id_verdict},
        "process": {"exit": wait["exit"], "timed_out": wait["timed_out"],
                    "reaped": stop["reaped"]},
        "cleanup": {"remaining_owned": stop["remaining_owned_qemu"],
                    "preexisting_unchanged": stop["preexisting_qemu_unchanged"],
                    "preexisting_reused": stop["preexisting_pid_reused"]},
        "custody": {"hashes_unchanged": hashes_unchanged,
                    "flush_ok": done_ok and not missing,
                    "missing_files": missing},
        "observation": {},
        "required_bodies": bodies,
        "actual_bodies": actual_bodies,
        "pins": staged,
        "executed": executed,
        "cleanup_required": cleanup_required,
        "cleanup_done": cleanup_done,
        "validation": validation,
    }


def body_files_present(scenario: str, body: str, run_dir: Path) -> bool:
    markers = {
        ("r01_det.sh", "leg-a"): ["ledger-legA.jsonl", "report-legA.json"],
        ("r01_det.sh", "leg-b"): ["ledger-legB.jsonl", "report-legB.json"],
        ("r01_floor.sh", "aggregate"): ["aggregate.json", "kernel-ref.json"],
        ("r01_floor.sh", "refusal"): ["refusal-rc.txt"],
        ("r02_dmcrypt.sh", "quiet-before"): ["product-quiet-before.json"],
        ("r02_dmcrypt.sh", "write"): ["product-write.json"],
        ("r02_dmcrypt.sh", "read"): ["product-read.json"],
        ("r02_dmcrypt.sh", "wrongkey"): ["workload.json"],
        ("r02_dmcrypt.sh", "quiet-after"): ["product-quiet-after.json"],
        ("r03_xfrm.sh", "quiet-before"): ["product-quiet-before.json"],
        ("r03_xfrm.sh", "main"): ["product-main.json", "ledger-a.json"],
        ("r03_xfrm.sh", "authfail"): ["product-authfail.json",
                                      "authfail-ledger.json"],
        ("r03_xfrm.sh", "quiet-after"): ["product-quiet-after.json"],
        ("r04_deny.sh", "refusal"): ["refusal-rc.txt"],
        ("r04_deny.sh", "control"): ["control.json", "kernel-ref.json"],
        ("r04_foreign.sh", "owned"): ["owned-pids.json", "product.json"],
        ("r04_foreign.sh", "foreign"): ["foreign-pids.json", "product.json"],
    }
    return all((run_dir / name).is_file()
               for name in markers.get((scenario, body), ["done.txt"]))


def load_report(cell_dir: Path, name: str) -> dict:
    return oracles.parse_api_returns_report(
        json.loads((cell_dir / name).read_text()))


def parse_rc(cell_dir: Path, name: str) -> int:
    """Parse a scenario rc file (`KEY=N` or bare `N`)."""
    text = (cell_dir / name).read_text().strip()
    return int(text.rsplit("=", 1)[-1])


def transport_closed(*parsed_reports: dict) -> bool:
    """Zero-loss gate over the parsed loss counters (fail-closed).

    Every counter in KNOWN_ZERO must read exactly "0". Counters in
    KNOWN_RECORDED (declared-boundary markers and the by-design
    C7 destroy skip) are recorded, never gated. Any UNKNOWN
    nonzero counter fails: new loss taxonomy must be classified
    deliberately, never absorbed.
    """
    for parsed in parsed_reports:
        for name, value in parsed["loss"].items():
            if name in KNOWN_RECORDED:
                continue
            if name in KNOWN_ZERO:
                if value != "0":
                    return False
            elif value != "0":
                return False
    return True


KNOWN_ZERO = frozenset({
    "ktot_gap",
    "ring_drops",
    "overflow_identities",
    "ring_reservation_failures",
    "user_queue_drops",
    "state_insert_failures",
    "budget_omissions",
    "predrop_cfg_fail",
    "predrop_fret_fail",
    "predrop_arg_null",
    "predrop_chase_fail",
    "predrop_name_fail",
    "predrop_spare_6",
    "predrop_spare_7",
})

KNOWN_RECORDED = frozenset({
    # Declared api-returns boundary (docs/kcrypto-evidence.md):
    # kernel delivery is unmeasured by design.
    "uncovered:kernel_delivery_unmeasured",
    # C7 by design (docs/kcrypto-support.md): destroy counted as
    # skip only (no exit-edge read).
    "predrop_destroy_skip",
})


def parse_fixture_stdout(text: str, op: str, count: int) -> bool:
    """Fixture truth markers: exact stdout lines + finished trailer."""
    if op == "hash":
        marker = f"hash: {count} digests done"
    else:
        marker = f"skcipher: {2 * count} ops done"
    return marker in text and "generator finished" in text


def judge_portion(manifest: dict, portion: dict, cell_dir: Path) -> dict:
    """Build oracle inputs from sealed files, run the predicate, reconcile.

    Returns the judged full receipt (in memory only — verify writes
    nothing) with ``_judgment`` carrying the verdict + reasons.
    """
    host_receipt = json.loads((cell_dir / "host-receipt.json").read_text())
    oracle_spec = portion["oracle"]
    scenario = portion["stimulus"]["scenario"]
    leak_hits = key_leak_scan(cell_dir)
    try:
        if scenario == "r01_det.sh":
            checks, detail, expected_body, actual_body = judge_r01_det(
                oracle_spec, cell_dir, host_receipt)
        elif scenario == "r01_floor.sh":
            checks, detail, expected_body, actual_body = judge_r01_floor(
                oracle_spec, cell_dir)
        elif scenario == "r02_dmcrypt.sh":
            checks, detail, expected_body, actual_body = judge_r02(
                oracle_spec, cell_dir)
        elif scenario == "r03_xfrm.sh":
            checks, detail, expected_body, actual_body = judge_r03(
                oracle_spec, cell_dir)
        elif scenario == "r04_deny.sh":
            checks, detail, expected_body, actual_body = judge_r04_deny(
                oracle_spec, cell_dir)
        elif scenario == "r04_foreign.sh":
            checks, detail, expected_body, actual_body = judge_r04_foreign(
                oracle_spec, cell_dir)
        else:
            raise oracles.OracleError(f"unknown scenario {scenario!r}")
    except (oracles.OracleError, KeyError, ValueError, json.JSONDecodeError) as err:
        checks = {"oracle_inputs_valid": False}
        detail = {"oracle_error": f"{type(err).__name__}: {err}"}
        expected_body, actual_body = {"error": "unjudgeable"}, {"error": str(err)}
    checks["identity_stable"] = bool(
        host_receipt.get("identity", {}).get("stable"))
    checks["manifest_bound"] = (
        host_receipt.get("manifest_sha256") == manifest["_manifest_sha256"])
    checks["guest_stage_match"] = guest_matches_stage(cell_dir, host_receipt)
    checks["no_key_leak"] = not leak_hits
    if leak_hits:
        detail["key_leak_hits"] = leak_hits
    full = dict(host_receipt)
    full["checks"] = {k: (v is True) for k, v in checks.items()}
    full["oracle_failed"] = sorted(k for k, v in checks.items() if v is not True)
    full["expected_body"] = expected_body
    full["actual_body"] = actual_body
    full["observation"] = {"expected": expected_body, "actual": actual_body,
                           "detail": detail}
    judgment = reconcile.verify_receipt(full)
    full["_judgment"] = judgment
    return full


def guest_matches_stage(cell_dir: Path, host_receipt: dict) -> bool:
    """In-guest environment hashes must equal the staged pins."""
    try:
        env = {}
        for line in (cell_dir / "environment.txt").read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                env[key.strip()] = value.strip()
        pins = host_receipt["pins"]
        return (
            env.get("ko") == pins.get("kcrypto_fixture.ko")
            and env.get("obj_agg") == pins.get("kryprobe-bpf/kcrypto.bpf.o")
            and env.get("obj_lc") == pins.get("kryprobe-bpf/kcrypto-lifecycle.bpf.o")
            and env.get("kryprobe") == pins.get("kryprobe")
        )
    except (OSError, KeyError):
        return False


def judge_r01_det(oracle_spec, cell_dir, host_receipt):
    legs = {}
    for leg, _run_id in (("legA", "t13r01a"), ("legB", "t13r01b")):
        sem = ledger_semantics(cell_dir / f"ledger-{leg}.jsonl")
        parsed = load_report(cell_dir, f"report-{leg}.json")
        product = {"/".join(str(part) for part in key): entry["calls"]
                   for key, entry in parsed["agg"].items()}
        legs[leg] = {
            "ledger_ops": sem["rows"],
            "ledger_phases": sem["phases"],
            "ledger_rc": host_receipt["validation"][leg]["rc"],
            "attach_markers": int(parsed["attach"].get("probes_attached", "0")),
            "attach_expected": int(parsed["attach"].get("probes_expected", "0")),
            "product": product,
            "transport_closed": transport_closed(parsed),
        }
    checks, detail = oracles.check_r01_det(
        {k: legs["legA"][k] for k in
         ("ledger_ops", "ledger_rc", "attach_markers", "product")},
        {k: legs["legB"][k] for k in
         ("ledger_ops", "ledger_rc", "attach_markers", "product")})
    checks["ledger_phases_deterministic"] = (
        legs["legA"]["ledger_phases"] == legs["legB"]["ledger_phases"])
    checks["attach_full"] = all(
        legs[leg]["attach_markers"] == legs[leg]["attach_expected"] > 0
        for leg in ("legA", "legB"))
    checks["transport_closed"] = all(
        legs[leg]["transport_closed"] for leg in ("legA", "legB"))
    detail["legs"] = {leg: {"ledger_ops": legs[leg]["ledger_ops"],
                            "attach": legs[leg]["attach_markers"]} for leg in legs}
    expected_body = {"ledger": legs["legA"]["ledger_phases"],
                     "product": legs["legA"]["product"]}
    actual_body = {"ledger": legs["legB"]["ledger_phases"],
                   "product": legs["legB"]["product"]}
    return checks, detail, expected_body, actual_body


def judge_r01_floor(oracle_spec, cell_dir):
    stdout = (cell_dir / "workload-stdout.log").read_text()
    workload = {
        "hash_issued": oracle_spec["hash_issued"],
        "hash_done": oracle_spec["hash_issued"] if parse_fixture_stdout(
            stdout, "hash", oracle_spec["hash_issued"]) else -1,
        "skc_issued": oracle_spec["skcipher_issued"],
        "skc_done": oracle_spec["skcipher_issued"] if parse_fixture_stdout(
            stdout, "skcipher", oracle_spec["skcipher_issued"]) else -1,
    }
    raw_ref = json.loads((cell_dir / "kernel-ref.json").read_text())["main"]
    kernel_ref = {name.removeprefix("crypto_"): value
                  for name, value in raw_ref.items()}
    parsed = load_report(cell_dir, "aggregate.json")
    product = {
        "ahash_digest": agg_calls(parsed, "ahash", "digest"),
        "shash_digest": agg_calls(parsed, "shash", "digest"),
        "skcipher_encrypt": agg_calls(parsed, "skcipher", "encrypt"),
        "skcipher_decrypt": agg_calls(parsed, "skcipher", "decrypt"),
        "ring_drops": parsed["loss"].get("ring_drops", "?"),
    }
    refusal = {"exit": parse_rc(cell_dir, "refusal-rc.txt"),
               "stderr": (cell_dir / "refusal-stderr.log").read_text()}
    checks, detail = oracles.check_r01_floor(workload, kernel_ref, product, refusal)
    checks["transport_closed"] = transport_closed(parsed)
    split = {}
    for key, entry in parsed["agg"].items():
        if key[0] == "skcipher" and key[2] == AGG_OK:
            split.setdefault(key[1], {})[key[3]] = entry["calls"]
    detail["skcipher_nesting_split"] = split
    checks["skcipher_nesting_split"] = (
        split.get("encrypt", {}).get("cbc(aes)") == workload["skc_issued"]
        and split.get("encrypt", {}).get("__cbc(aes)") == workload["skc_issued"]
        and split.get("decrypt", {}).get("cbc(aes)") == workload["skc_issued"]
        and split.get("decrypt", {}).get("__cbc(aes)") == workload["skc_issued"])
    expected_body = {"ahash_digest": workload["hash_issued"],
                     "shash_digest": workload["hash_issued"],
                     "skcipher_encrypt": 2 * workload["skc_issued"],
                     "skcipher_decrypt": 2 * workload["skc_issued"]}
    actual_body = {k: kernel_ref[k] for k in expected_body}
    return checks, detail, expected_body, actual_body


def stimulus_identical(cell_dir: Path, ft_name: str, p_name: str,
                       sha_key: str, bytes_key: str) -> bool:
    """Split-leg stimulus identity: the ftrace-only and product-only
    sub-legs moved the same bytes with the same checksum."""
    try:
        ft = json.loads((cell_dir / ft_name).read_text())
        prod = json.loads((cell_dir / p_name).read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    return (ft.get(sha_key) == prod.get(sha_key)
            and ft.get(sha_key) is not None
            and ft.get(bytes_key) == prod.get(bytes_key)
            and (ft.get(bytes_key) or 0) > 0)


def judge_r02(oracle_spec, cell_dir):
    workload = json.loads((cell_dir / "workload.json").read_text())
    kernel = json.loads((cell_dir / "kernel-ref.json").read_text())["windows"]
    parsed_write = load_report(cell_dir, "product-write.json")
    parsed_read = load_report(cell_dir, "product-read.json")
    parsed_qb = load_report(cell_dir, "product-quiet-before.json")
    parsed_qa = load_report(cell_dir, "product-quiet-after.json")
    kernel_ref = {
        "skcipher_encrypt": (kernel["write"].get("crypto_skcipher_encrypt", 0)
                             + kernel["read"].get("crypto_skcipher_encrypt", 0)),
        "skcipher_decrypt": (kernel["write"].get("crypto_skcipher_decrypt", 0)
                             + kernel["read"].get("crypto_skcipher_decrypt", 0)),
    }
    product = {
        "skcipher_encrypt": agg_calls(parsed_write, "skcipher", "encrypt"),
        "skcipher_decrypt": agg_calls(parsed_read, "skcipher", "decrypt"),
        "enc_bytes": agg_bytes(parsed_write, "skcipher", "encrypt"),
        "dec_bytes": agg_bytes(parsed_read, "skcipher", "decrypt"),
        "ring_drops": ("0" if parsed_write["loss"].get("ring_drops") == "0"
                       and parsed_read["loss"].get("ring_drops") == "0" else "N"),
    }

    def quiet(parsed, window):
        rows = sum(entry["calls"] for entry in parsed["agg"].values())
        return {"product_rows": rows,
                "kernel_hits": sum(window.get(k, 0) for k in window)}

    checks, detail = oracles.check_r02(
        workload, kernel_ref, product,
        quiet(parsed_qb, kernel["quiet-before"]),
        quiet(parsed_qa, kernel["quiet-after"]))
    checks["wrongkey_mismatch"] = workload.get("wrongkey_checksum_mismatch") is True
    checks["stimulus_write_identical"] = stimulus_identical(
        cell_dir, "leg-write-ftrace.json", "leg-write.json",
        "write_sha256", "bytes_written")
    checks["stimulus_read_identical"] = stimulus_identical(
        cell_dir, "leg-read-ftrace.json", "leg-read.json",
        "read_sha256", "bytes_read")
    checks["transport_closed"] = transport_closed(
        parsed_write, parsed_read, parsed_qb, parsed_qa)
    detail["kernel_method"] = json.loads(
        (cell_dir / "kernel-ref.json").read_text())["method"]
    expected_body = {"bytes_written": oracle_spec["bytes_each_direction"],
                     "bytes_read": oracle_spec["bytes_each_direction"],
                     "checksums_match": True}
    actual_body = {"bytes_written": workload["bytes_written"],
                   "bytes_read": workload["bytes_read"],
                   "checksums_match": workload["checksums_match"]}
    return checks, detail, expected_body, actual_body


def judge_r03(oracle_spec, cell_dir):
    ledger_a = json.loads((cell_dir / "ledger-a.json").read_text())
    ledger_b = json.loads((cell_dir / "ledger-b.json").read_text())
    authfail_ledger = json.loads((cell_dir / "authfail-ledger.json").read_text())
    kernel = json.loads((cell_dir / "kernel-ref.json").read_text())["windows"]
    parsed_main = load_report(cell_dir, "product-main.json")
    parsed_auth = load_report(cell_dir, "product-authfail.json")
    parsed_qb = load_report(cell_dir, "product-quiet-before.json")
    parsed_qa = load_report(cell_dir, "product-quiet-after.json")
    kernel_ref = {
        "aead_encrypt": kernel["main"].get("crypto_aead_encrypt", 0),
        "aead_decrypt": kernel["main"].get("crypto_aead_decrypt", 0),
    }
    product = {
        "aead_encrypt": agg_calls(parsed_main, "aead", "encrypt"),
        "aead_decrypt": agg_calls(parsed_main, "aead", "decrypt"),
        "ring_drops": parsed_main["loss"].get("ring_drops", "?"),
    }
    authfail_product = {
        "aead_encrypt": agg_calls(parsed_auth, "aead", "encrypt"),
        "aead_decrypt": agg_calls(parsed_auth, "aead", "decrypt"),
        "aead_decrypt_errors": agg_calls(parsed_auth, "aead", "decrypt", "error"),
        "error_errnos": [row["first_errno"] for row in parsed_auth["who"]
                         if row.get("first_errno") is not None],
        "ring_drops": parsed_auth["loss"].get("ring_drops", "?"),
    }

    def quiet(parsed, window):
        rows = sum(entry["calls"] for entry in parsed["agg"].values())
        return {"product_rows": rows,
                "kernel_hits": sum(window.get(k, 0) for k in window)}

    checks, detail = oracles.check_r03(
        ledger_a, ledger_b, kernel_ref, product,
        authfail_ledger, authfail_product,
        quiet(parsed_qb, kernel["quiet-before"]),
        quiet(parsed_qa, kernel["quiet-after"]))
    checks["transport_closed"] = transport_closed(
        parsed_main, parsed_auth, parsed_qb, parsed_qa)
    detail["kernel_method"] = json.loads(
        (cell_dir / "kernel-ref.json").read_text())["method"]
    expected_body = {"sent_a": oracle_spec["packets_each_direction"],
                     "sent_b": oracle_spec["packets_each_direction"],
                     "authfail_sent": oracle_spec["authfail_packets"]}
    actual_body = {"sent_a": ledger_a["sent"], "sent_b": ledger_b["sent"],
                   "authfail_sent": authfail_ledger["sent"]}
    return checks, detail, expected_body, actual_body


def judge_r04_deny(oracle_spec, cell_dir):
    refusal = {"exit": parse_rc(cell_dir, "refusal-rc.txt"),
               "stderr": (cell_dir / "refusal-stderr.log").read_text()}
    stdout = (cell_dir / "control-stdout.log").read_text()
    kernel_ref = json.loads((cell_dir / "kernel-ref.json").read_text())["main"]
    parsed = load_report(cell_dir, "control.json")
    observed = {}
    for name in kernel_ref:
        _before, _sep, func = name.partition("crypto_")
        fam = "ahash" if func.startswith("ahash") else (
            "shash" if func.startswith("shash") else None)
        if fam is None:
            raise oracles.OracleError(f"kernel_ref names unexpected {name!r}")
        entry = parsed["agg"].get((fam, "digest", AGG_OK))
        observed[name] = entry["calls"] if entry else 0
    control = {
        "hash_issued": oracle_spec["control_issued"],
        "hash_done": oracle_spec["control_issued"] if parse_fixture_stdout(
            stdout, "hash", oracle_spec["control_issued"]) else -1,
        "observed": observed,
        "ring_drops": parsed["loss"].get("ring_drops", "?"),
    }
    checks, detail = oracles.check_r04_deny(refusal, control, kernel_ref)
    checks["transport_closed"] = transport_closed(parsed)
    expected_body = {"refusal_exit": oracle_spec["refusal_exit"],
                     "control_done": oracle_spec["control_issued"]}
    actual_body = {"refusal_exit": refusal["exit"],
                   "control_done": control["hash_done"]}
    return checks, detail, expected_body, actual_body


def judge_r04_foreign(oracle_spec, cell_dir):
    owned = json.loads((cell_dir / "owned-pids.json").read_text())
    foreign = json.loads((cell_dir / "foreign-pids.json").read_text())
    parsed = load_report(cell_dir, "product.json")
    agg_digest_total = sum(
        entry["calls"] for key, entry in parsed["agg"].items()
        if key[0] in ("ahash", "shash") and key[2] == AGG_OK)
    checks, detail = oracles.check_r04_foreign(
        owned["pids"], foreign["pids"],
        oracle_spec["owned_issued"], oracle_spec["foreign_issued"],
        parsed["who"], agg_digest_total)
    checks["transport_closed"] = transport_closed(parsed)
    checks["no_unexpected_results"] = all(
        key[2] == AGG_OK for key in parsed["agg"]
        if key[0] in ("ahash", "shash"))
    owned_done = "hash: %d digests done" % oracle_spec["owned_issued"] in (
        cell_dir / "owned-stdout.log").read_text()
    foreign_done = "hash: %d digests done" % oracle_spec["foreign_issued"] in (
        cell_dir / "foreign-stdout.log").read_text()
    checks["workloads_proved"] = bool(owned_done and foreign_done)
    detail["pid_no_reuse"] = {
        "owned_start_ticks": owned.get("start_ticks"),
        "foreign_start_ticks": foreign.get("start_ticks"),
    }
    expected_body = {"owned": oracle_spec["owned_issued"],
                     "foreign": oracle_spec["foreign_issued"]}
    actual_body = {"owned": oracle_spec["owned_issued"] if owned_done else -1,
                   "foreign": oracle_spec["foreign_issued"] if foreign_done else -1}
    return checks, detail, expected_body, actual_body


def cmd_verify(args) -> int:
    manifest = kinputs.load_inputs(Path(args.manifest))
    cells_dir = Path(args.cells_dir)
    required = [p["id"] for cell in kinputs.t13_cells(manifest)
                for p in cell["portions"]]
    judged = []
    for portion_id in sorted(required):
        portion = find_portion(manifest, portion_id)[1]
        cell_dir = cells_dir / portion_id
        if not cell_dir.is_dir():
            print(f"{portion_id}: MISSING (no sealed cell)")
            judged.append({"portion_id": portion_id, "verdict": "NOT_RUN",
                           "reason": "sealed cell absent",
                           "positive_control": "harness RED/GREEN suites"})
            continue
        full = judge_portion(manifest, portion, cell_dir)
        verdict = full["_judgment"]["verdict"]
        print(f"{portion_id}: {verdict}")
        for reason in full["_judgment"]["reasons"]:
            print(f"  - {reason}")
        judged.append(full)
    summary = reconcile.reconcile_campaign(required, judged,
                                           uniform_pins=UNIFORM_PINS)
    print(f"campaign: {summary['verdict']}")
    for reason in summary["reasons"]:
        print(f"  - {reason}")
    for portion_id, verdict in sorted(summary["per_portion"].items()):
        print(f"  {portion_id} = {verdict}")
    return 0 if summary["verdict"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="T13 consumer campaign CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="list runnable portions")
    plan.add_argument("--manifest", required=True)
    run = sub.add_parser("run", help="run one portion in an owned guest")
    run.add_argument("--manifest", required=True)
    run.add_argument("--portion", required=True)
    run.add_argument("--kryprobe", required=True)
    run.add_argument("--bpf-dir", required=True)
    run.add_argument("--ko", action="append", default=[],
                     help="K=V prebuilt fixture .ko (r01_det only)")
    run.add_argument("--fixture", required=True)
    run.add_argument("--out-root", required=True)
    run.add_argument("--lock", action="append", required=True)
    run.add_argument("--evidence-dir", required=True)
    verify = sub.add_parser("verify", help="judge sealed cells (offline)")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--cells-dir", required=True)
    args = parser.parse_args()
    if args.command == "plan":
        return cmd_plan(args)
    if args.command == "run":
        return cmd_run(args)
    return cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
