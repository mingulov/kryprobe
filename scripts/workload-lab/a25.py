#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed-product acceptance journeys (Task05 Stage 4, G11b/A25).

Installed watch/report/scoped-policy paths, deterministic replay,
v1-legacy migration, saturation, and unavailable-metadata cases —
each against an independent oracle (exit-code table per F06,
fixture self-counts, byte-identical replay, recomputed ledger
math). Runs ONLY in an owned guest under lease against the real
installed path (dev-flow install.sh without --stage, so the
cap-free helper sibling ships). Every journey writes a 13.3
receipt to --out.

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
            "saturation", "unavailable-metadata")

# F06 exit-code family for workload-qualified report/check ops.
EXPECTED_EXITS = {"complete": 0, "usage": 2, "cannot-establish": 3,
                  "env-unusable": 4, "violation": 10}

FROZEN_UNAVAILABLE = ("no_principal", "helper_refused",
                      "budget_exceeded", "unsupported_environment",
                      "parse_failed")

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
        "installed check: clean (0), violation (10), "
        "unevaluable (3), bad policy (2), scoped legs",
        "oracle: F06 exit table + never-10-without-evidence",
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
        "root, no-flag, corrupt-file, and no-helper legs",
        "oracle: frozen typed reasons + raw rows + exit 3",
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
    if proc.returncode != EXPECTED_EXITS["complete"]:
        raise LabError(f"clean policy rc={proc.returncode}, want 0")
    out["clean"] = {"rc": 0, "driver_ops": summary["ops_total"]}
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

    def _case(name: str, cmd: list, want: str | None) -> dict:
        traffic, ledger = start_traffic(driver, args.out, name,
                                        meas=8, warm=2)
        try:
            report = args.out / f"a25-unavail-{name}.json"
            proc = run(cmd + ["--out", str(report)], 120)
            summary = reap_traffic(traffic, ledger, name, 60)
        finally:
            if traffic.poll() is None:
                traffic.kill()
        if proc.returncode != EXPECTED_EXITS["cannot-establish"]:
            raise LabError(f"{name}: rc={proc.returncode}, want 3")
        doc = json.loads(report.read_text())
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

    base = ["kryprobe", "report", "--system", "--duration", "12",
            "--format", "workload-json"]
    if os.geteuid() == 0:
        out["root"] = _case("root",
                            base + ["--workload-metadata",
                                    str(meta)], "no_principal")
    else:
        out["root"] = {"skipped": "needs euid 0"}
    uid, gid = nonroot_principal()
    out["no-flag"] = _case(
        "no-flag",
        ["setpriv", f"--reuid={uid}", f"--regid={gid}",
         "--clear-groups"] + base
        if (uid, gid) != (os.geteuid(), os.getegid()) else base,
        None)
    corrupt = args.out / "a25-corrupt-metadata.json"
    corrupt.write_text("{not json")
    helperless = args.out / "no-helper-bin"
    if os.geteuid() == 0:
        helperless.mkdir(exist_ok=True)
        shutil.copyfile(caps["kryprobe"],
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
                    journey_unavailable_metadata}
        return legs[args.journey](args)
    except LabError as err:
        print(f"{args.journey} FAIL: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
