#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed-product acceptance journeys (Task05 Stage 4, G11b/A25).

Installed watch/report/scoped-policy paths, deterministic replay,
v1-legacy migration, saturation, unavailable-metadata, and
faulted-pipe (EPIPE) cases — each against an independent oracle
(exit-code table per F06, fixture self-counts, byte-identical
replay, recomputed ledger math, typed refusal markers). Runs ONLY
in an owned guest under lease against the real installed path
(dev-flow install.sh without --stage, so the cap-free helper
sibling ships). Every journey writes a 13.3 receipt to --out.

Unrunnable on this host (no guests, disk full): --dry-run prints
the planned steps with exact NOT_RUN state and exits 0 without
side effects; --help lists the journeys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common as lab  # noqa: E402
from docker_lab import LabError, run, utcnow, write_receipt  # noqa: E402

JOURNEYS = ("watch", "report", "policy", "replay", "migration",
            "saturation", "unavailable-metadata", "epipe")

# F06 exit-code family for workload-qualified report/check ops,
# plus the truncated-stdout member (docs/commands.md "Truncated
# stdout (1A-L11)": live.rs emit_stdout_text maps a torn stdout to
# 1 with a typed marker; main.rs STDOUT_FAILED is the same 1 as
# the guard backstop for an otherwise-0 exit).
EXPECTED_EXITS = {"complete": 0, "usage": 2, "cannot-establish": 3,
                  "env-unusable": 4, "violation": 10,
                  "truncated-stdout": 1}

# C7-1 EPIPE: the typed stdout-failure marker the product emits on
# a torn stream (live.rs emit_stdout_text "{tool}: cannot write
# stdout"; pinned per-command by the cmd_report.rs/cmd_watch.rs
# unit tests and the kcrypto_output.rs integration suite — the
# same typed discipline as the Stage-3
# malformed_metadata_is_rejected precedent: exact marker, never
# bare nonzero).
EPIPE_STDERR_MARKER = "report: cannot write stdout"

FROZEN_UNAVAILABLE = ("no_principal", "helper_refused",
                      "budget_exceeded", "unsupported_environment",
                      "parse_failed")

# F1: live windows fail closed to INCONCLUSIVE by construction
# (eval.rs: Clean needs overall CompleteForDeclaredBoundary;
# capture-integrity + completion read weaker on every live window —
# D1a characterized exactly this kp2 §8 pair). The journey pins
# rc=3 AND the named dims, never rc alone.
EXPECTED_CLEAN_MISSING = ("capture-integrity", "completion")

# F1: the unconstructible clean->0 leg is recorded NOT_RUN, never
# faked: `check` takes a live capture only (no stored-input surface
# in args.rs Command::Check), and CLEAN needs COMPLETE coverage per
# docs/policy.md — unreachable on live windows.
CLEAN_ZERO_NOT_RUN_REASON = (
    "check takes a live capture only (args.rs Command::Check has no "
    "stored-input surface); CLEAN needs COMPLETE coverage per "
    "docs/policy.md, unreachable on live windows "
    "(capture-integrity + completion gaps by construction)")


def parse_inconclusive_dims(stdout: str) -> list | None:
    """Wire dims from an `INCONCLUSIVE missing=a,b` verdict line
    (None when the verdict line is absent). Pure — host-tested."""
    for line in stdout.splitlines():
        if line.startswith("INCONCLUSIVE missing="):
            dims = line[len("INCONCLUSIVE missing="):]
            return [dim for dim in dims.split(",") if dim]
    return None


def check_noflag_available_unresolved(doc: dict) -> list:
    """Optional-file semantics pin (F2): without
    `--workload-metadata` the serve still succeeds, so status reads
    `available` (status describes the serving path, not the file —
    the taxonomy has no no-file variant) with every per-key answer
    Unresolved: bare rows carry neither `workload` nor a
    non-unresolved `attribution` (assemble.rs split_row keeps the
    bare default implicit). Returns reasons (empty = pinned). Pure —
    host-tested."""
    reasons = []
    metadata = doc.get("metadata", {}) if isinstance(doc, dict) \
        else {}
    if metadata.get("status") != "available":
        reasons.append(f"status={metadata.get('status')!r}, want "
                       "'available'")
    if "reason" in metadata:
        reasons.append(f"available carries reason="
                       f"{metadata['reason']!r}")
    contexts = doc.get("contexts", []) if isinstance(doc, dict) \
        else []
    if not contexts:
        reasons.append("no raw rows (blocked?)")
    for idx, row in enumerate(contexts):
        if not isinstance(row, dict):
            reasons.append(f"contexts[{idx}] not an object")
            continue
        if "workload" in row:
            reasons.append(f"contexts[{idx}] carries workload "
                           "identity (want Unresolved)")
        attribution = row.get("attribution")
        if attribution is not None:
            status = attribution.get("status") \
                if isinstance(attribution, dict) else None
            if status != "unresolved":
                reasons.append(
                    f"contexts[{idx}].attribution.status="
                    f"{status!r} (want 'unresolved')")
    return reasons


def stage_helperless_copy(src: Path, dst: Path) -> None:
    """Stage the helperless-leg CLI copy (F2): copyfile drops the
    exec bit and `token mint` sets the xattr only (cmd_token.rs), so
    chmod +x explicitly — without it the leg cannot exec the copy."""
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o755)


def parse_pins_env(text: str) -> dict:
    """Parse staged `pins.env` (`KEY="hex"` lines) into {key:
    value}. Blanks and comments skipped. Pure — host-tested."""
    pins = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = value.strip().strip('"')
    return pins


EPIPE_SEAL_DIMS = (("kryprobe", "CLI_SHA"),
                   ("kryprobe-workload-helper", "HELPER_SHA"),
                   ("kryprobe-bpf/kcrypto.bpf.o", "AGG_SHA"),
                   ("kryprobe-bpf/kcrypto-lifecycle.bpf.o", "LC_SHA"))


def check_epipe_seal(installed: dict, pins: dict) -> list:
    """Installed bytes == K seal on all 4 dims (C7-1 leg
    precondition). Returns reasons (empty = sealed). Pure —
    host-tested."""
    reasons = []
    for name, key in EPIPE_SEAL_DIMS:
        want = pins.get(key, "")
        if len(want) != 64:
            reasons.append(f"seal pin {key} missing/malformed")
        elif installed.get(name, "") != want:
            reasons.append(f"installed {name} != K seal")
    return reasons


def check_epipe_outcome(rc: int, stderr: str, attempts: int) -> list:
    """Typed EPIPE oracle: exactly exit 1 (the exit family's
    truncated-stdout member) plus the exact typed stderr marker,
    on exactly one attempt (single-attempt semantics — no retry
    pile-up). Exit 0 is the never-clean violation; any other
    nonzero without the marker is untyped. Returns reasons
    (empty = typed refusal). Pure — host-tested."""
    reasons = []
    if attempts != 1:
        reasons.append(f"attempts={attempts}, want exactly 1 "
                       "(no retry pile-up)")
    if rc == 0:
        reasons.append("clean exit 0 over a torn stdout "
                       "(must refuse)")
    elif rc != EXPECTED_EXITS["truncated-stdout"]:
        reasons.append(f"rc={rc}, want "
                       f"{EXPECTED_EXITS['truncated-stdout']} "
                       "(typed truncated-stdout)")
    if EPIPE_STDERR_MARKER not in stderr:
        reasons.append(f"stderr lacks typed marker "
                       f"{EPIPE_STDERR_MARKER!r}")
    return reasons


def run_with_closed_stdout(cmd: list, timeout_s: float):
    """Run one command with stdout on a readerless pipe (C7-1
    EPIPE): the read end closes BEFORE spawn, so the kernel fails
    the first stdout write deterministically with EPIPE (Rust
    ignores SIGPIPE, so the failure surfaces as a write error —
    never a signal death — per docs/commands.md 1A-L11). No
    reader process, no timing. Returns (proc, stderr, wall_s).
    C7-2 grace in the budget; a hang kills and raises LabError."""
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    start = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                stdout=write_fd,
                                stderr=subprocess.PIPE, text=True)
    finally:
        os.close(write_fd)
    budget = timeout_s + lab.OWNED_REAP_GRACE_S
    try:
        _, stderr = proc.communicate(timeout=budget)
    except subprocess.TimeoutExpired as err:
        proc.kill()
        proc.wait()
        raise LabError(
            f"EPIPE probe hung: {cmd[0]} exceeded {budget:.0f}s "
            f"(budget {timeout_s:.0f}s + 1s reap grace)") from err
    return proc, stderr, time.monotonic() - start

DRY_RUN_STEPS = {
    "watch": [
        "installed watch --system over M1-driver traffic",
        "oracle: rc 0 + rows observed + driver ops > 0; "
        "bare watch refuses 2",
    ],
    "report": [
        "installed workload-json as root (no_principal) and as "
        "non-root (available) + offline ledger re-verification",
        "oracle: typed states + recomputed sums; /dev/full legs "
        "refuse (C7-1/A10)",
    ],
    "policy": [
        "installed check: clean (3 + named missing dims — "
        "fail-closed on live windows), violation (10), "
        "unevaluable (3), bad policy (2), scoped legs",
        "clean->0 replay is NOT_RUN (no stored-input surface; "
        "CLEAN needs COMPLETE coverage)",
        "oracle: F06 exit table + named dims + "
        "never-10-without-evidence",
    ],
    "replay": [
        "report FILE twice over stored workload-json bytes",
        "oracle: byte-identical render; tampered copy refuses 2",
    ],
    "migration": [
        "report over stored v1 bytes (valid, scoped, truncated)",
        "oracle: limitations render (3), scope refusal (2), "
        "invalid refusal (2)",
    ],
    "saturation": [
        "churn_full-shaped load under workload-json capture",
        "oracle: rows 1024 + unknown==drops > 0 + refused > 0 + "
        "bounded shutdown",
    ],
    "unavailable-metadata": [
        "root, no-flag (available + all-Unresolved), corrupt-file, "
        "and no-helper legs",
        "oracle: frozen typed reasons + available/Unresolved pin + "
        "raw rows + exit 3",
    ],
    "epipe": [
        "installed report --system to a readerless stdout pipe "
        "under M1-driver traffic (single attempt)",
        "oracle: exit 1 + typed 'report: cannot write stdout' "
        "(never 0); attempts==1; traffic sentinel non-exited "
        "after + ops > 0; installed bytes == K seal from "
        "--seal-file",
    ],
}


def _is_digit_str(value) -> bool:
    return isinstance(value, str) and bool(value) and all(
        char in "0123456789" for char in value)


def check_workload_report(doc: dict) -> list:
    """Offline workload-report-v2 re-verification (deterministic
    rendering without runtime state): required keys, wire types,
    the recomputed row/ledger/partition identities. Scope-value
    pins (unscoped/none) stay with the calling journey. Pure —
    host-tested. Returns reasons (empty = valid)."""
    reasons = []
    if not isinstance(doc, dict):
        return ["report not an object"]
    for key in ("schema", "session", "interval", "profile",
                "boundary", "dictionary", "contexts", "ledger",
                "partition", "selectors", "scope", "metadata",
                "coverage"):
        if key not in doc:
            reasons.append(f"lacks {key!r}")
    if reasons:
        return reasons
    if doc["schema"] != "kryprobe.workload-report.v2":
        reasons.append(f"schema {doc['schema']!r} refused")
    session_id = doc["session"].get("session_id", "")
    if len(session_id) != 32 or any(
            char not in "0123456789abcdef" for char in session_id):
        reasons.append("session_id not 32 lowercase hex")
    contexts = doc["contexts"]
    if not isinstance(contexts, list):
        return reasons + ["contexts not a list"]
    rows_sum = 0
    for idx, row in enumerate(contexts):
        calls = (row.get("calls") if isinstance(row, dict)
                 else None)
        if not _is_digit_str(calls):
            reasons.append(f"contexts[{idx}].calls mistyped")
        else:
            rows_sum += int(calls)
    ledger = doc["ledger"]
    for key in ("system_total", "per_context_sum", "unknown",
                "refused_inserts"):
        if not _is_digit_str(ledger.get(key)):
            reasons.append(f"ledger.{key} mistyped")
    if doc["interval"].get("consistency") != \
            ledger.get("consistency"):
        reasons.append("interval/ledger consistency disagree")
    if _is_digit_str(ledger.get("per_context_sum")) and \
            rows_sum != int(ledger["per_context_sum"]):
        reasons.append(f"rows sum {rows_sum} != per_context_sum "
                       f"{ledger['per_context_sum']}")
    partition = doc["partition"]
    part_sum = 0
    for key in ("matched", "nonmatched", "unknown_match"):
        if not _is_digit_str(partition.get(key)):
            reasons.append(f"partition.{key} mistyped")
        else:
            part_sum += int(partition[key])
    if part_sum != rows_sum:
        reasons.append(f"partition observed {part_sum} != rows "
                       f"sum {rows_sum}")
    return reasons


def a25_preflight() -> dict:
    """Installed-product capability probe (no docker needed)."""
    kryprobe = shutil.which("kryprobe")
    if kryprobe is None:
        raise LabError("guest lacks installed kryprobe")
    status = run(["kryprobe", "token", "status", "--bin", kryprobe],
                 30)
    if status.returncode != 0:
        raise LabError("installed kryprobe has no caps: "
                       f"{status.stderr.strip()}")
    try:
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind(("skcipher", "cbc(aes)"))
        sock.close()
    except OSError as err:
        raise LabError(f"AF_ALG cbc(aes) unavailable: {err}")
    if not Path("/sys/kernel/btf/vmlinux").is_file():
        raise LabError("kernel BTF absent")
    helper = Path(kryprobe).parent / "kryprobe-workload-helper"
    return {"kryprobe": kryprobe, "helper": str(helper),
            "helper_present": helper.is_file()}


def need_driver(args) -> Path:
    if not args.driver:
        raise LabError("--driver is required for live legs")
    driver = Path(args.driver)
    if not driver.is_file():
        raise LabError(f"driver {driver} missing in guest")
    return driver


def start_traffic(driver: Path, out: Path, name: str,
                  size: int = 4096, meas: int = 12, warm: int = 2,
                  extra: list | None = None):
    """Start one M1-driver traffic run (Popen; caller reaps)."""
    ledger = out / f"{name}.csv"
    cmd = ["python3", str(driver), "skcipher", str(size),
           str(meas), str(warm)]
    cmd.extend(extra or [])
    cmd.append(str(ledger))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    return proc, ledger


def reap_traffic(proc, ledger: Path, name: str,
                 timeout_s: float) -> dict:
    """Reap one traffic run (C7-2 grace in the budget) and return
    its summary (traffic proof for the oracles)."""
    try:
        _, stderr = proc.communicate(
            timeout=timeout_s + lab.OWNED_REAP_GRACE_S)
    except subprocess.TimeoutExpired as err:
        proc.kill()
        raise LabError(f"{name} did not exit") from err
    if proc.returncode != 0:
        raise LabError(f"{name} rc={proc.returncode}: "
                       f"{stderr.strip()[-300:]}")
    summary = json.loads(
        Path(str(ledger) + ".summary.json").read_text())
    if summary.get("fails"):
        raise LabError(f"{name} fails={summary['fails']}")
    return summary


def nonroot_principal() -> tuple:
    """The non-root principal for metadata legs: self when already
    unprivileged, else the owned a25bench account (created)."""
    import pwd

    if os.geteuid() != 0:
        return os.geteuid(), os.getegid()
    try:
        entry = pwd.getpwnam("a25bench")
        return entry.pw_uid, entry.pw_gid
    except KeyError:
        pass
    if shutil.which("setpriv") is None:
        raise LabError("guest lacks setpriv")
    proc = run(["useradd", "-M", "-s", "/usr/sbin/nologin",
                "a25bench"], 60)
    if proc.returncode != 0:
        raise LabError("cannot create a25bench")
    entry = pwd.getpwnam("a25bench")
    return entry.pw_uid, entry.pw_gid


def as_principal(cmd: list, uid: int, gid: int) -> list:
    """Wrap one command to run as (uid, gid) via setpriv
    (exec semantics keep sampler/wait/kill pids correct)."""
    if uid == os.geteuid() and gid == os.getegid():
        return cmd
    return ["setpriv", f"--reuid={uid}", f"--regid={gid}",
            "--clear-groups"] + cmd


def parse_ctx_line(stderr_path: Path) -> dict:
    """Last terminal ctx object from a capture stderr log."""
    prefix = "kryprobe: telemetry "
    found = None
    for line in Path(stderr_path).read_text().splitlines():
        if not line.startswith(prefix):
            continue
        try:
            obj = json.loads(line[len(prefix):])
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("ctx"),
                                                dict):
            found = obj["ctx"]
    if found is None:
        raise LabError(f"{stderr_path}: no ctx telemetry object")
    return found


def journey_watch(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    traffic, ledger = start_traffic(driver, args.out, "watch")
    try:
        time.sleep(3)
        # C7-3: the sentinel verifies non-exited (never bare
        # kill(pid, 0) — it matches zombies too).
        if lab.proc_exited(traffic.pid):
            raise LabError("traffic died mid-watch")
        proc = run(["kryprobe", "watch", "--system",
                    "--duration", "10"], 60)
    finally:
        summary = reap_traffic(traffic, ledger, "watch-traffic",
                               60)
    if proc.returncode != EXPECTED_EXITS["complete"]:
        raise LabError(f"watch rc={proc.returncode}, want 0")
    if not proc.stdout.strip():
        raise LabError("watch observed no rows under traffic")
    if summary["ops_total"] <= 0:
        raise LabError("traffic proof empty (no driver ops)")
    neg = run(["kryprobe", "watch"], 30)
    if neg.returncode != EXPECTED_EXITS["usage"]:
        raise LabError(f"bare watch rc={neg.returncode}, want 2")
    write_receipt(args.out, "a25-watch",
                  {"started_utc": utcnow(), "caps": caps,
                   "watch_bytes": len(proc.stdout),
                   "driver_ops": summary["ops_total"],
                   "bare_watch_rc": neg.returncode,
                   "verdict": "PASS"})
    print(f"watch PASS: {len(proc.stdout)} bytes over "
          f"{summary['ops_total']} driver ops")
    return 0


def journey_report(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    if not args.metadata:
        raise LabError("--metadata is required for live legs")
    meta = Path(args.metadata)
    if not meta.is_file():
        raise LabError(f"metadata {meta} missing in guest")
    out: dict = {}
    if os.geteuid() == 0:
        traffic, ledger = start_traffic(driver, args.out,
                                        "report-root")
        try:
            proc = run(["kryprobe", "report", "--system",
                        "--duration", "12", "--format",
                        "workload-json", "--workload-metadata",
                        str(meta), "--out",
                        str(args.out / "report-root.json")], 120)
            summary = reap_traffic(traffic, ledger, "report-root",
                                   60)
        finally:
            if traffic.poll() is None:
                traffic.kill()
        if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
            raise LabError(f"root report rc={proc.returncode}, "
                           "want 3")
        doc = json.loads((args.out / "report-root.json").read_text())
        if doc["metadata"].get("status") != "unavailable" or \
                doc["metadata"].get("reason") != "no_principal":
            raise LabError("root report is not no_principal")
        out["root"] = {"reason": "no_principal",
                       "rows": len(doc["contexts"]),
                       "driver_ops": summary["ops_total"]}
    else:
        out["root"] = {"skipped": "needs euid 0"}
    uid, gid = nonroot_principal()
    traffic, ledger = start_traffic(driver, args.out, "report-m")
    try:
        proc = run(as_principal(
            ["kryprobe", "report", "--system", "--duration", "12",
             "--format", "workload-json", "--workload-metadata",
             str(meta), "--out",
             str(args.out / "report-m.json")], uid, gid), 120)
        summary = reap_traffic(traffic, ledger, "report-m", 60)
    finally:
        if traffic.poll() is None:
            traffic.kill()
    if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
        raise LabError(f"M report rc={proc.returncode}, want 3")
    raw = (args.out / "report-m.json").read_bytes()
    if len(raw) > 1048576:
        raise LabError("report over the 1 MiB budget")
    doc = json.loads(raw)
    reasons = check_workload_report(doc)
    if reasons:
        raise LabError(f"offline re-verification: {reasons}")
    if doc["metadata"].get("status") != "available":
        raise LabError(f"M report status="
                       f"{doc['metadata'].get('status')}")
    out["m"] = {"rows": len(doc["contexts"]),
                "coverage": doc["coverage"],
                "driver_ops": summary["ops_total"]}
    # C7-1/A10: output failures through the installed CLI refuse
    # (never a clean complete over truncated evidence).
    full = run(["kryprobe", "report", "--system", "--duration",
                "2", "--format", "workload-json", "--out",
                "/dev/full"], 60)
    if full.returncode == 0:
        raise LabError("--out /dev/full exited 0 (must refuse)")
    out["dev_full_rc"] = full.returncode
    write_receipt(args.out, "a25-report",
                  {"started_utc": utcnow(), "caps": caps, **out,
                   "verdict": "PASS"})
    print(f"report PASS: root={out['root']} m-rows="
          f"{out['m']['rows']} dev-full-rc={full.returncode}")
    return 0


CLEAN_POLICY = """\
version: 1
rules:
  - id: no-kernel-md5
    source: kernel-crypto
    match:
      stage: returned
      algorithm: md5
    decision: deny
"""

VIOLATION_POLICY = """\
version: 1
rules:
  - id: deny-cbc-aes
    source: kernel-crypto
    match:
      stage: returned
      algorithm: cbc(aes)
    decision: deny
"""

INCONCLUSIVE_POLICY = """\
version: 1
rules:
  - id: needs-module
    source: kernel-crypto
    match:
      stage: returned
      module: no-such-module
    decision: deny
"""

BAD_POLICY = """\
version: 1
unknown_top_key: true
rules: []
"""


def _check_with_traffic(args, driver, policy: Path, name: str,
                        extra: list | None = None) -> object:
    traffic, ledger = start_traffic(driver, args.out, name)
    try:
        cmd = ["kryprobe", "check", "--system", "--policy",
               str(policy), "--duration", "12"]
        cmd.extend(extra or [])
        proc = run(cmd, 120)
        summary = reap_traffic(traffic, ledger, name, 60)
    finally:
        if traffic.poll() is None:
            traffic.kill()
    return proc, summary


def journey_policy(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    pol_dir = args.out / "policies"
    pol_dir.mkdir(parents=True, exist_ok=True)
    clean = pol_dir / "clean.yaml"
    clean.write_text(CLEAN_POLICY)
    violation = pol_dir / "violation.yaml"
    violation.write_text(VIOLATION_POLICY)
    inconclusive = pol_dir / "inconclusive.yaml"
    inconclusive.write_text(INCONCLUSIVE_POLICY)
    bad = pol_dir / "bad.yaml"
    bad.write_text(BAD_POLICY)
    out: dict = {}
    proc, summary = _check_with_traffic(args, driver, clean,
                                        "policy-clean")
    if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
        raise LabError(f"clean policy rc={proc.returncode}, want 3 "
                       "(fail-closed on live windows)")
    dims = parse_inconclusive_dims(proc.stdout)
    if dims is None:
        raise LabError("clean policy names no missing dims")
    if set(dims) != set(EXPECTED_CLEAN_MISSING):
        raise LabError(f"clean policy missing={dims}, want "
                       f"{list(EXPECTED_CLEAN_MISSING)}")
    out["clean"] = {"rc": 3, "missing": dims,
                    "driver_ops": summary["ops_total"]}
    out["clean_zero_replay"] = {"status": "NOT_RUN",
                                "reason": CLEAN_ZERO_NOT_RUN_REASON}
    proc, summary = _check_with_traffic(args, driver, violation,
                                        "policy-violation")
    if proc.returncode != EXPECTED_EXITS["violation"]:
        raise LabError(f"violation policy rc={proc.returncode}, "
                       "want 10")
    if "VIOLATION" not in proc.stdout:
        raise LabError("violation verdict unnamed")
    out["violation"] = {"rc": 10,
                        "driver_ops": summary["ops_total"]}
    proc, _ = _check_with_traffic(args, driver, inconclusive,
                                  "policy-inconclusive")
    if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
        raise LabError(f"unevaluable policy rc={proc.returncode}, "
                       "want 3")
    out["inconclusive"] = {"rc": 3}
    proc, _ = _check_with_traffic(args, driver, bad, "policy-bad")
    if proc.returncode != EXPECTED_EXITS["usage"]:
        raise LabError(f"bad policy rc={proc.returncode}, want 2")
    out["bad"] = {"rc": 2}
    # Scoped legs: violation inside the traffic scope, never a
    # violation from an empty scope (never-10-without-evidence).
    if os.geteuid() == 0:
        traffic, ledger = start_traffic(driver, args.out,
                                        "policy-scope")
        try:
            cg_dir = Path("/sys/fs/cgroup") / f"{lab.LAB_TAG}-scope"
            cg_dir.mkdir(exist_ok=True)
            (cg_dir / "cgroup.procs").write_text(
                str(traffic.pid))
            cg_id = str(cg_dir.stat().st_ino)
            cmd = ["kryprobe", "check", "--system", "--policy",
                   str(violation), "--duration", "14",
                   "--filter-cgroup-id", cg_id]
            proc = run(cmd, 120)
            summary = reap_traffic(traffic, ledger,
                                   "policy-scope", 60)
        finally:
            if traffic.poll() is None:
                traffic.kill()
        if proc.returncode != EXPECTED_EXITS["violation"]:
            raise LabError("scoped violation rc="
                           f"{proc.returncode}, want 10")
        out["scoped_hit"] = {"rc": 10, "cgroup_id": cg_id}
        empty_dir = Path("/sys/fs/cgroup") / f"{lab.LAB_TAG}-empty"
        empty_dir.mkdir(exist_ok=True)
        empty_id = str(empty_dir.stat().st_ino)
        traffic, ledger = start_traffic(driver, args.out,
                                        "policy-scope-empty")
        try:
            proc = run(["kryprobe", "check", "--system",
                        "--policy", str(violation), "--duration",
                        "14", "--filter-cgroup-id", empty_id], 120)
            reap_traffic(traffic, ledger, "policy-scope-empty",
                         60)
        finally:
            if traffic.poll() is None:
                traffic.kill()
        if proc.returncode == EXPECTED_EXITS["violation"]:
            raise LabError("empty scope raised a violation (10 "
                           "without evidence)")
        out["scoped_empty"] = {"rc": proc.returncode}
        for path in (cg_dir, empty_dir):
            try:
                path.rmdir()
            except OSError:
                pass
    else:
        out["scoped_hit"] = {"skipped": "needs euid 0"}
        out["scoped_empty"] = {"skipped": "needs euid 0"}
    write_receipt(args.out, "a25-policy",
                  {"started_utc": utcnow(), "caps": caps, **out,
                   "verdict": "PASS"})
    print(f"policy PASS: {out}")
    return 0


def journey_replay(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    traffic, ledger = start_traffic(driver, args.out, "replay")
    try:
        proc = run(["kryprobe", "report", "--system",
                    "--duration", "10", "--format",
                    "workload-json", "--out",
                    str(args.out / "replay-stored.json")], 120)
        summary = reap_traffic(traffic, ledger, "replay", 60)
    finally:
        if traffic.poll() is None:
            traffic.kill()
    if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
        raise LabError(f"stored capture rc={proc.returncode}, "
                       "want 3")
    stored = args.out / "replay-stored.json"
    first = run(["kryprobe", "report", str(stored)], 60)
    second = run(["kryprobe", "report", str(stored)], 60)
    if first.returncode != second.returncode:
        raise LabError("replay exit unstable: "
                       f"{first.returncode} vs {second.returncode}")
    sha1 = hashlib.sha256(first.stdout.encode()).hexdigest()
    sha2 = hashlib.sha256(second.stdout.encode()).hexdigest()
    if sha1 != sha2:
        raise LabError("replay render not deterministic")
    tampered = args.out / "replay-tampered.json"
    raw = bytearray(stored.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    tampered.write_bytes(bytes(raw))
    bad = run(["kryprobe", "report", str(tampered)], 60)
    if bad.returncode != EXPECTED_EXITS["usage"]:
        raise LabError(f"tampered replay rc={bad.returncode}, "
                       "want 2")
    write_receipt(args.out, "a25-replay",
                  {"started_utc": utcnow(), "caps": caps,
                   "render_sha256": sha1, "rc": first.returncode,
                   "tamper_rc": bad.returncode,
                   "driver_ops": summary["ops_total"],
                   "verdict": "PASS"})
    print(f"replay PASS: render {sha1[:12]}... stable, tamper "
          "refused")
    return 0


def journey_migration(args) -> int:
    caps = a25_preflight()
    if not args.v1_file:
        raise LabError("--v1-file is required (stage "
                       "tests/fixtures/workload_report_v1_sample.json)")
    v1 = Path(args.v1_file)
    if not v1.is_file():
        raise LabError(f"v1 sample {v1} missing in guest")
    proc = run(["kryprobe", "report", str(v1)], 60)
    if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
        raise LabError(f"v1 render rc={proc.returncode}, want 3")
    if "limitations" not in proc.stdout:
        raise LabError("v1 render names no limitations")
    scoped = json.loads(v1.read_text())
    scoped["selectors"] = {"kind": "cgroup-id",
                           "cgroup_id": "43812"}
    scoped_path = args.out / "v1-scoped.json"
    scoped_path.write_text(json.dumps(scoped))
    proc = run(["kryprobe", "report", str(scoped_path)], 60)
    if proc.returncode != EXPECTED_EXITS["usage"]:
        raise LabError(f"scoped v1 rc={proc.returncode}, want 2")
    truncated = args.out / "v1-truncated.json"
    truncated.write_bytes(v1.read_bytes()[:-50])
    proc = run(["kryprobe", "report", str(truncated)], 60)
    if proc.returncode != EXPECTED_EXITS["usage"]:
        raise LabError(f"truncated v1 rc={proc.returncode}, want 2")
    write_receipt(args.out, "a25-migration",
                  {"started_utc": utcnow(), "caps": caps,
                   "render_rc": 3, "scoped_rc": 2,
                   "truncated_rc": 2, "verdict": "PASS"})
    print("migration PASS: v1 renders with limitations (3), scope "
          "+ truncation refuse (2)")
    return 0


def journey_saturation(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    report = args.out / "saturation.report.workload-json"
    stderr_log = args.out / "saturation-capture.stderr.log"
    capture = subprocess.Popen(
        ["kryprobe", "report", "--system", "--duration", "45",
         "--format", "workload-json", "--out", str(report)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        traffic, ledger = start_traffic(
            driver, args.out, "saturation", meas=30, warm=10,
            extra=["--churn-every-ms", "50", "--churn-ops", "8"])
        try:
            summary = reap_traffic(traffic, ledger, "saturation",
                                   120)
        finally:
            if traffic.poll() is None:
                traffic.kill()
        try:
            _, stderr = capture.communicate(
                timeout=45 + 30 + lab.OWNED_REAP_GRACE_S)
        except subprocess.TimeoutExpired as err:
            capture.kill()
            raise LabError("capture did not shut down bounded") \
                from err
    except LabError:
        if capture.poll() is None:
            capture.kill()
        raise
    if capture.returncode != EXPECTED_EXITS["cannot-establish"]:
        raise LabError(f"saturation rc={capture.returncode}, want 3")
    stderr_log.write_text(stderr)
    ctx = parse_ctx_line(stderr_log)
    doc = json.loads(report.read_text())
    reasons = check_workload_report(doc)
    if reasons:
        raise LabError(f"report re-verification: {reasons}")
    if ctx.get("rows") != 1024:
        raise LabError(f"ctx rows={ctx.get('rows')}, want 1024")
    if doc["ledger"].get("refused_inserts") == "0":
        raise LabError("refused_inserts silent under saturation")
    unknown, drops = ctx.get("unknown_calls"), ctx.get("drops")
    if unknown != drops or not unknown:
        raise LabError(f"unknown={unknown} drops={drops}: "
                       "saturation must show unknown==drops > 0")
    if len(doc["contexts"]) != 1024:
        raise LabError(f"report rows={len(doc['contexts'])}, "
                       "want 1024")
    write_receipt(args.out, "a25-saturation",
                  {"started_utc": utcnow(), "caps": caps,
                   "ctx": ctx,
                   "refused": doc["ledger"]["refused_inserts"],
                   "driver_ops": summary["ops_total"],
                   "verdict": "PASS"})
    print(f"saturation PASS: rows 1024, unknown==drops={unknown}, "
          f"refused={doc['ledger']['refused_inserts']}")
    return 0


def journey_unavailable_metadata(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    if not args.metadata:
        raise LabError("--metadata is required for live legs")
    meta = Path(args.metadata)
    out: dict = {}

    def _run_capture(name: str, cmd: list) -> tuple:
        """One unavailable-family capture: driver traffic under a
        workload-json report, both reaped. Returns (proc, doc,
        summary); oracles stay with the callers."""
        traffic, ledger = start_traffic(driver, args.out, name,
                                        meas=8, warm=2)
        try:
            report = args.out / f"a25-unavail-{name}.json"
            proc = run(cmd + ["--out", str(report)], 120)
            summary = reap_traffic(traffic, ledger, name, 60)
        finally:
            if traffic.poll() is None:
                traffic.kill()
        return proc, json.loads(report.read_text()), summary

    def _case(name: str, cmd: list, want: str | None) -> dict:
        proc, doc, summary = _run_capture(name, cmd)
        if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
            raise LabError(f"{name}: rc={proc.returncode}, want 3")
        status = doc.get("metadata", {}).get("status")
        reason = doc.get("metadata", {}).get("reason")
        if status != "unavailable":
            raise LabError(f"{name}: status={status}")
        if reason not in FROZEN_UNAVAILABLE:
            raise LabError(f"{name}: reason={reason!r} outside "
                           "the frozen vocabulary")
        if want is not None and reason != want:
            raise LabError(f"{name}: reason={reason}, want {want}")
        if not doc.get("contexts"):
            raise LabError(f"{name}: no raw rows (blocked?)")
        return {"reason": reason, "rows": len(doc["contexts"]),
                "driver_ops": summary["ops_total"]}

    def _case_available(name: str, cmd: list) -> dict:
        """F2 no-flag case: the optional file is absent but the
        serve succeeds — status `available` with every per-key
        answer Unresolved."""
        proc, doc, summary = _run_capture(name, cmd)
        if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
            raise LabError(f"{name}: rc={proc.returncode}, want 3")
        reasons = check_noflag_available_unresolved(doc)
        if reasons:
            raise LabError(f"{name}: {reasons}")
        return {"status": "available",
                "unresolved_rows": len(doc["contexts"]),
                "driver_ops": summary["ops_total"]}

    base = ["kryprobe", "report", "--system", "--duration", "12",
            "--format", "workload-json"]
    if os.geteuid() == 0:
        out["root"] = _case("root",
                            base + ["--workload-metadata",
                                    str(meta)], "no_principal")
    else:
        out["root"] = {"skipped": "needs euid 0"}
    uid, gid = nonroot_principal()
    out["no-flag"] = _case_available(
        "no-flag",
        ["setpriv", f"--reuid={uid}", f"--regid={gid}",
         "--clear-groups"] + base
        if (uid, gid) != (os.geteuid(), os.getegid()) else base)
    corrupt = args.out / "a25-corrupt-metadata.json"
    corrupt.write_text("{not json")
    helperless = args.out / "no-helper-bin"
    if os.geteuid() == 0:
        helperless.mkdir(exist_ok=True)
        stage_helperless_copy(Path(caps["kryprobe"]),
                              helperless / "kryprobe")
        shutil.copytree(Path(caps["kryprobe"]).parent /
                        "kryprobe-bpf",
                        helperless / "kryprobe-bpf",
                        dirs_exist_ok=True)
        mint = run([caps["kryprobe"], "token", "mint", "--force",
                    "--bin", str(helperless / "kryprobe")], 60)
        if mint.returncode != 0:
            raise LabError("mint --force on the helperless copy "
                           f"failed: {mint.stderr.strip()[-200:]}")
        out["no-helper"] = _case(
            "no-helper",
            ["setpriv", f"--reuid={uid}", f"--regid={gid}",
             "--clear-groups", str(helperless / "kryprobe"),
             "report", "--system", "--duration", "12", "--format",
             "workload-json", "--workload-metadata", str(meta)],
            "helper_refused")
    else:
        out["no-helper"] = {"skipped": "needs euid 0"}
    out["corrupt-file"] = _case(
        "corrupt-file",
        (["setpriv", f"--reuid={uid}", f"--regid={gid}",
          "--clear-groups"] if (uid, gid) != (os.geteuid(),
                                             os.getegid())
         else []) + base + ["--workload-metadata", str(corrupt)],
        None)
    write_receipt(args.out, "a25-unavailable-metadata",
                  {"started_utc": utcnow(), "caps": caps, **out,
                   "verdict": "PASS"})
    print(f"unavailable-metadata PASS: {out}")
    return 0


def journey_epipe(args) -> int:
    caps = a25_preflight()
    driver = need_driver(args)
    if not args.seal_file:
        raise LabError("--seal-file is required (staged pins.env)")
    seal_path = Path(args.seal_file)
    if not seal_path.is_file():
        raise LabError(f"seal file {seal_path} missing in guest")
    pins = parse_pins_env(seal_path.read_text())
    bindir = Path(caps["kryprobe"]).parent
    installed = {}
    for name, _ in EPIPE_SEAL_DIMS:
        target = bindir / name
        if not target.is_file():
            raise LabError(f"installed {name} missing under "
                           f"{bindir}")
        installed[name] = hashlib.sha256(
            target.read_bytes()).hexdigest()
    reasons = check_epipe_seal(installed, pins)
    if reasons:
        raise LabError(f"K-seal mismatch: {reasons}")
    # Traffic outlives the 10 s capture by design (meas 20 +
    # warm 2), so the sentinel is still running when the torn
    # CLI exits — an exited sentinel is a setup failure, never
    # evidence.
    traffic, ledger = start_traffic(driver, args.out, "epipe",
                                    meas=20, warm=2)
    try:
        # The single EPIPE attempt: a live report renders to a
        # readerless stdout pipe, so the first write fails with
        # EPIPE mid-stream (no retry loop exists by
        # construction).
        proc, stderr, wall_s = run_with_closed_stdout(
            ["kryprobe", "report", "--system", "--duration", "10",
             "--format", "human"], 120)
        attempts = 1
        # C7-3: the traffic sentinel must be non-exited after
        # the torn CLI run (never bare kill(pid, 0) — it
        # matches zombies too).
        sentinel_alive = not lab.proc_exited(traffic.pid)
        summary = reap_traffic(traffic, ledger, "epipe-traffic",
                               60)
    finally:
        if traffic.poll() is None:
            traffic.kill()
    if not sentinel_alive:
        raise LabError("traffic sentinel exited during the EPIPE "
                       "probe (setup inconclusive)")
    if summary["ops_total"] <= 0:
        raise LabError("traffic proof empty (no driver ops)")
    reasons = check_epipe_outcome(proc.returncode, stderr,
                                  attempts)
    if reasons:
        raise LabError(f"EPIPE oracle: {reasons} "
                       f"(rc={proc.returncode}, stderr tail: "
                       f"{stderr.strip()[-300:]!r})")
    write_receipt(args.out, "a25-epipe",
                  {"started_utc": utcnow(), "caps": caps,
                   "seal": "4/4 MATCH",
                   "rc": proc.returncode,
                   "stderr_marker": EPIPE_STDERR_MARKER,
                   "wall_s": round(wall_s, 2),
                   "attempts": attempts,
                   "sentinel": "ALIVE(post-probe, non-exited)",
                   "driver_ops": summary["ops_total"],
                   "verdict": "PASS"})
    print(f"epipe PASS: rc={proc.returncode} "
          f"marker={EPIPE_STDERR_MARKER!r} wall={wall_s:.1f}s "
          f"attempts={attempts} sentinel=ALIVE "
          f"ops={summary['ops_total']}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="a25.py",
        description="Installed-product acceptance (A25/G11b).")
    parser.add_argument("--dry-run", action="store_true",
                        help="print planned steps + NOT_RUN, no "
                        "side effects")
    parser.add_argument("--out", type=Path,
                        default=Path("a25-out"),
                        help="receipt/output dir")
    parser.add_argument("--driver", default="",
                        help="M1 driver path in guest")
    parser.add_argument("--metadata", default="",
                        help="metadata file in guest")
    parser.add_argument("--v1-file", default="",
                        help="stored v1 bytes (migration leg)")
    parser.add_argument("--seal-file", default="",
                        help="staged pins.env (epipe leg seal)")
    parser.add_argument("journey", choices=JOURNEYS)
    args = parser.parse_args(argv)
    if args.dry_run:
        print(f"journey: {args.journey} (owned guest required)")
        for step in DRY_RUN_STEPS[args.journey]:
            print(f"  step: {step}")
        print("NOT_RUN: live guest + installed product needed; "
              "no side effects performed (host disk full, no "
              "lease consumed)")
        return 0
    try:
        legs = {"watch": journey_watch, "report": journey_report,
                "policy": journey_policy, "replay": journey_replay,
                "migration": journey_migration,
                "saturation": journey_saturation,
                "unavailable-metadata":
                    journey_unavailable_metadata,
                "epipe": journey_epipe}
        return legs[args.journey](args)
    except LabError as err:
        print(f"{args.journey} FAIL: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
