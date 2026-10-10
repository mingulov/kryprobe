#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned-guest Docker-lab helpers (Task05 Stage 4, freeze G11a).

Spec 11.7 labs: two workloads stay distinct (identical comm +
algorithm, distinct cgroups), container termination/recreation,
unavailable-metadata controls, and the userspace-TLS negative
with a kernel-crypto positive control -- every claim against an
independent oracle (fixture self-counts vs BPF observation), with
a no-unrelated-resources inventory diff and idempotent cleanup.

Runs ONLY in an owned guest under lease (never dockerd on the
shared host). The guest needs Docker, the installed kryprobe
(dev-flow install.sh: CLI + file caps + helper sibling), python3,
and openssl. Every journey writes a 13.3 receipt to --out.

Unrunnable on this host (no guests, disk full): --dry-run prints
the planned steps with exact NOT_RUN state and exits 0 without
side effects; --help lists the journeys.
"""

from __future__ import annotations

import argparse
import datetime
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

JOURNEYS = ("setup", "two-workloads", "termination",
            "unavailable-metadata", "tls", "cleanup")

# F3: fixture containers execute the M1 driver (AF_ALG skcipher),
# which the default container confinement refuses twice: seccomp
# blocks the PF_ALG autoload (EPERM) and the AppArmor docker-default
# profile denies the socket (EACCES) — pairwise isolated in round-1
# DIAG2b, and both-relaxed proven minimal in DIAG2c (exit 0, 258425
# ops, fails=0). Every driver-executing `docker run` in the fixture
# path carries both opts via fixture_docker_run(). Fixtures are test
# workloads; kryprobe observes from outside, so relaxed fixture
# confinement does not weaken the observation. Ledger-fetch and
# sleep-holder runs execute no driver and stay default-confined.
FIXTURE_SECURITY_OPTS = ["--security-opt", "seccomp=unconfined",
                         "--security-opt", "apparmor=unconfined"]

# F3: the receipt disclosure carried by every fixture-running
# journey (two-workloads, termination, unavailable-metadata, tls).
FIXTURE_CONFINEMENT_NOTE = (
    "relaxed on driver-executing fixture runs only "
    "(seccomp=unconfined + apparmor=unconfined, proven minimal "
    "DIAG2c exit 0 / 258425 ops / fails=0); fixtures are test "
    "workloads, kryprobe observes from outside")


def fixture_docker_run(*rest: str) -> list:
    """`docker run` argv for driver-executing fixture containers (F3:
    both security-opts relaxed — proven minimal)."""
    return ["docker", "run", *FIXTURE_SECURITY_OPTS, *rest]


def termination_sleep_argv(tag: str, name: str) -> list:
    """`docker run` argv for the F4 termination-hold container: the
    frozen driver has no sleep mode (usage rc=2), so `--entrypoint
    sleep` keeps sleep semantics while bypassing the driver
    entrypoint entirely."""
    return ["docker", "run", "-d", "--rm", "--entrypoint", "sleep",
            "--name", name, fixture_image_tag(tag), "300"]


def _wait_container_gone(name: str, timeout_s: float = 30.0) -> None:
    """Wait until `name` no longer exists (termination-leg reuse
    guard: `--rm` auto-removal races an immediate reuse of the name —
    the daemon still reports the stopped container as in use)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = run(["docker", "inspect", "--format",
                    "{{.State.Status}}", name], 30)
        if proc.returncode != 0:
            return
        time.sleep(1)
    raise LabError(f"{name} still present after stop (remove race?)")


def _wait_tcp_listen(host: str, port: int, timeout_s: float,
                     proc) -> None:
    """Wait until host:port accepts (TLS-leg readiness: s_server
    needs a moment after fork; connecting early refuses). Raises
    with the server's stderr tail if the server dies first. The
    probe connection is opened and closed without I/O."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            raise LabError("TLS server died during startup: "
                           f"{stderr.strip()[-300:]}")
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            return
        except OSError:
            time.sleep(0.5)
    raise LabError(f"TLS server not listening on {host}:{port} "
                   f"after {timeout_s:.0f}s")


def _wait_capture_tick(stderr_path: Path, capture,
                       timeout_s: float = 60.0) -> None:
    """Wait for the capture's first progress tick (two-workloads
    attach guard: ticks flow only post-attach — the progress closure
    is installed after production.open() in live.rs — so the first
    tick proves the sensor is observing before subject traffic
    starts. Without it the head subject loses its first ~2 s to the
    attach window and exact reconciliation fails. Fails if the
    capture dies first or no tick arrives in budget."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if capture.poll() is not None:
            raise LabError("capture died before first tick "
                           f"(rc={capture.poll()})")
        try:
            text = Path(stderr_path).read_text()
        except OSError:
            text = ""
        if "progress tick=" in text:
            return
        time.sleep(0.5)
    raise LabError(f"capture emitted no progress tick in "
                   f"{timeout_s:.0f}s")

DRY_RUN_STEPS = {
    "setup": [
        "preflight: docker, installed kryprobe + caps, AF_ALG, "
        "cgroup v2, BTF, openssl",
        "build the owned fixture image (M1 driver inside)",
        "snapshot the docker/cgroup inventory (cleanup oracle)",
    ],
    "two-workloads": [
        "docker_two_workloads_stay_distinct: two containers, "
        "identical comm + cbc(aes), distinct cgroups",
        "kryprobe workload-json capture over both fixture runs "
        "(first progress tick proves attach before subjects run)",
        "fixture runs carry relaxed seccomp+apparmor (F3: test "
        "workloads; kryprobe observes from outside)",
        "oracle: per-cgroup enc/dec == fixture self-counted ops",
    ],
    "termination": [
        "stop/rm one --entrypoint-sleep container (F4), await its "
        "removal, recreate under the same name",
        "fixture runs carry relaxed seccomp+apparmor (F3: test "
        "workloads; kryprobe observes from outside)",
        "oracle: new cgroup id (never reused), fresh traffic "
        "attributes to it, old id absent",
    ],
    "unavailable-metadata": [
        "metadata-less, corrupt-file, and root/no_principal legs",
        "fixture runs carry relaxed seccomp+apparmor (F3: test "
        "workloads; kryprobe observes from outside)",
        "oracle: typed unavailable + raw rows + exit 3 on each",
    ],
    "tls": [
        "userspace-TLS transfer in owned cgroups (kTLS evidence; "
        "server readiness-polled)",
        "fixture runs carry relaxed seccomp+apparmor (F3: test "
        "workloads; kryprobe observes from outside)",
        "oracle: zero kernel-crypto calls there; AF_ALG positive "
        "control exact",
    ],
    "cleanup": [
        "remove owned containers/network/volume/image (idempotent)",
        "oracle: inventory diff shows no unrelated change",
    ],
}


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


class LabError(Exception):
    """A lab step failed (recorded in the receipt, exit 1)."""


def run(cmd: list, timeout_s: float, **kwargs):
    """Run one lab command (C7-2: the enclosing budget always adds
    the 1 s owned-reap grace to the attempt deadline)."""
    budget = timeout_s + lab.OWNED_REAP_GRACE_S
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=budget, **kwargs)
    except subprocess.TimeoutExpired as err:
        raise LabError(f"timeout after {budget:.0f}s: {cmd[0]} "
                       f"(budget {timeout_s:.0f}s + 1s reap grace)"
                       ) from err


def need_cmd(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise LabError(f"guest lacks {name}")
    return path


def preflight() -> dict:
    """Guest capability probe (versions recorded, never assumed)."""
    need_cmd("docker")
    need_cmd("kryprobe")
    need_cmd("openssl")
    info = run(["docker", "info", "--format", "{{json .}}"], 30)
    if info.returncode != 0:
        raise LabError(f"docker info failed: {info.stderr.strip()}")
    server = json.loads(info.stdout).get("ServerVersion", "?")
    mint = run(["kryprobe", "token", "status", "--bin",
                shutil.which("kryprobe")], 30)
    if mint.returncode != 0:
        raise LabError("installed kryprobe has no caps "
                       f"(token status: {mint.stderr.strip()})")
    try:
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind(("skcipher", "cbc(aes)"))
        sock.close()
    except OSError as err:
        raise LabError(f"AF_ALG cbc(aes) unavailable: {err}")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise LabError("cgroup v2 controllers absent")
    if not Path("/sys/kernel/btf/vmlinux").is_file():
        raise LabError("kernel BTF absent")
    out = run(["openssl", "version"], 30)
    return {"docker": server,
            "openssl": out.stdout.strip() if out.returncode == 0
            else "unknown"}


def cgroup_id_of_pid(pid: int) -> str:
    """Numeric cgroup v2 ID (cgroupfs inode) of one process."""
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    except OSError as err:
        raise LabError(f"cannot read cgroup of {pid}: {err}")
    for entry in lines:
        _n, _, path = entry.partition("::")
        if not path or path == "/":
            continue
        target = Path("/sys/fs/cgroup") / path.lstrip("/")
        try:
            return str(target.stat().st_ino)
        except OSError as err:
            raise LabError(f"cannot stat {target}: {err}")
    raise LabError(f"no cgroup path for pid {pid}")


def docker_inventory() -> dict:
    """Structured docker inventory (F08: explicit structured
    output only, never decorative tables)."""
    inv: dict = {}
    names = run(["docker", "ps", "-a", "--format", "{{.Names}}"], 60)
    if names.returncode != 0:
        raise LabError(f"docker ps failed: {names.stderr.strip()}")
    inv["containers"] = sorted(names.stdout.split())
    nets = run(["docker", "network", "ls", "--format", "{{.Name}}"],
               60)
    if nets.returncode != 0:
        raise LabError(
            f"docker network ls failed: {nets.stderr.strip()}")
    inv["networks"] = sorted(nets.stdout.split())
    vols = run(["docker", "volume", "ls", "--format", "{{.Name}}"],
               60)
    if vols.returncode != 0:
        raise LabError(
            f"docker volume ls failed: {vols.stderr.strip()}")
    inv["volumes"] = sorted(vols.stdout.split())
    imgs = run(["docker", "images", "--format",
                "{{.Repository}}:{{.Tag}}"], 60)
    if imgs.returncode != 0:
        raise LabError(f"docker images failed: {imgs.stderr.strip()}")
    inv["images"] = sorted(imgs.stdout.split())
    return inv


def write_receipt(out_dir: Path, journey: str, record: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{journey}.receipt.json"
    record = {"journey": journey, "ended_utc": utcnow(), **record}
    path.write_text(json.dumps(record, indent=1) + "\n")
    return path


def fixture_image_tag(tag: str) -> str:
    return f"{tag}-fixture:latest"


def build_fixture_image(tag: str, driver: Path,
                        out_dir: Path) -> dict:
    """Build the owned fixture image (python + M1 driver). The
    image digest is recorded (pin-by-record); reruns compare."""
    context = out_dir / "fixture-context"
    context.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(driver, context / "kcrypto_perf_m1.py")
    (context / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "COPY kcrypto_perf_m1.py /lab/kcrypto_perf_m1.py\n"
        'ENTRYPOINT ["python3", "/lab/kcrypto_perf_m1.py"]\n')
    proc = run(["docker", "build", "-t", fixture_image_tag(tag),
                str(context)], 600)
    if proc.returncode != 0:
        raise LabError(f"docker build failed: {proc.stderr.strip()}")
    inspect = run(["docker", "images", "--digests", "--format",
                   "{{json .}}", fixture_image_tag(tag)], 60)
    digest = ""
    if inspect.returncode == 0 and inspect.stdout.strip():
        digest = json.loads(inspect.stdout.splitlines()[0]).get(
            "Digest", "")
    return {"tag": fixture_image_tag(tag), "digest": digest,
            "driver": str(driver)}


def container_pid(name: str) -> int:
    proc = run(["docker", "inspect", "--format", "{{.State.Pid}}",
                name], 30)
    if proc.returncode != 0:
        raise LabError(f"inspect {name} failed: {proc.stderr.strip()}")
    try:
        return int(proc.stdout.strip())
    except ValueError as err:
        raise LabError(f"inspect {name}: bad pid") from err


KOP_ALLOC, KOP_ENC, KOP_DEC = 1, 3, 4


def fold_cgroup_calls(report_path: Path) -> dict:
    """Fold workload-json contexts by cgroup_id into {cgroup:
    {enc, dec, alloc, calls}} by native op numerics (frozen ABI:
    ALLOC=1, ENC=3, DEC=4). Live v2 reports use dictionary form
    (rows carry native_ref; ops live in the dictionary), so refs
    resolve first; inline native objects are accepted too. An
    unresolvable op counts its calls but classifies nothing
    (fail-open on counts, closed on classification). Pure —
    host-tested."""
    doc = json.loads(Path(report_path).read_text())
    by_ref: dict = {}
    dictionary = doc.get("dictionary")
    if isinstance(dictionary, list):
        for entry in dictionary:
            if isinstance(entry, dict) and \
                    entry.get("dict_id") is not None:
                by_ref[entry["dict_id"]] = entry
    folded: dict = {}
    for row in doc.get("contexts", []):
        cgroup = row.get("cgroup_id")
        native = row.get("native") or {}
        if not native and row.get("native_ref") is not None:
            native = by_ref.get(row["native_ref"]) or {}
        calls = int(row.get("calls", "0"))
        slot = folded.setdefault(
            cgroup, {"enc": 0, "dec": 0, "alloc": 0, "calls": 0})
        slot["calls"] += calls
        op = native.get("op")
        if op == KOP_ENC:
            slot["enc"] += calls
        elif op == KOP_DEC:
            slot["dec"] += calls
        elif op == KOP_ALLOC:
            slot["alloc"] += calls
    return folded


def journey_setup(args) -> int:
    versions = preflight()
    image = build_fixture_image(args.tag, Path(args.driver),
                                args.out)
    vol = f"{args.tag}-ledgers"
    proc = run(["docker", "volume", "create", vol], 60)
    if proc.returncode != 0:
        raise LabError(
            f"volume create failed: {proc.stderr.strip()}")
    before = docker_inventory()
    (args.out / "inventory-before.json").write_text(
        json.dumps(before, indent=1) + "\n")
    write_receipt(args.out, "setup",
                  {"started_utc": utcnow(), "versions": versions,
                   "image": image, "volume": vol,
                   "inventory": before, "verdict": "READY"})
    print(f"setup READY: image {image['tag']} digest "
          f"{image['digest'] or 'unresolved'}")
    return 0


def _running_pid(name: str) -> int:
    """Container PID once the runtime has started it (short
    poll: inspect reports 0 while starting)."""
    for _ in range(10):
        pid = container_pid(name)
        if pid > 0:
            return pid
        time.sleep(1)
    raise LabError(f"{name} never started (pid 0)")


def _run_fixture(tag: str, name: str, ledger_name: str,
                 size: int = 4096, meas: int = 10,
                 warm: int = 2) -> dict:
    """Run one fixture container (single shape) detached; sample
    its OWN cgroup id + comm while running, wait for exit, fetch
    its self-counted ledger, and remove it. Returns the summary
    with cgroup_id + comm attached."""
    vol = f"{tag}-ledgers"
    proc = run(fixture_docker_run(
        "-d", "--name", name, "-v", f"{vol}:/ledgers",
        fixture_image_tag(tag), "skcipher", str(size),
        str(meas), str(warm), f"/ledgers/{ledger_name}"), 60)
    if proc.returncode != 0:
        raise LabError(f"fixture {name} start failed: "
                       f"{proc.stderr.strip()[-300:]}")
    try:
        pid = _running_pid(name)
        cgroup = cgroup_id_of_pid(pid)
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError as err:
            raise LabError(f"cannot read comm of {pid}: {err}")
        waited = run(["docker", "wait", name], meas + warm + 120)
    finally:
        run(["docker", "rm", "-f", name], 60)
    if waited.returncode != 0 or waited.stdout.strip() != "0":
        raise LabError(f"fixture {name} exit="
                       f"{waited.stdout.strip()}")
    show = run(["docker", "run", "--rm", "--entrypoint", "python3",
                "-v", f"{vol}:/ledgers", fixture_image_tag(tag),
                "-c", "import json;print(open('/ledgers/"
                f"{ledger_name}.summary.json').read())"], 60)
    if show.returncode != 0:
        raise LabError(f"ledger fetch {name} failed")
    summary = json.loads(show.stdout)
    summary["cgroup_id"] = cgroup
    summary["comm"] = comm
    return summary


def journey_two_workloads(args) -> int:
    """docker_two_workloads_stay_distinct: identical comm +
    algorithm, distinct cgroups, reconciled independently."""
    name_a, name_b = f"{args.tag}-a", f"{args.tag}-b"
    report = args.out / "two-workloads.report.workload-json"
    capture_err = args.out / "two-workloads.capture.stderr.log"
    err_file = open(capture_err, "w")
    try:
        capture = subprocess.Popen(
            ["kryprobe", "report", "--system", "--duration", "60",
             "--format", "workload-json", "--out", str(report)],
            stdout=subprocess.PIPE, stderr=err_file, text=True)
        try:
            _wait_capture_tick(capture_err, capture)
        except LabError:
            if capture.poll() is None:
                capture.kill()
                try:
                    capture.wait(
                        timeout=lab.OWNED_REAP_GRACE_S + 5)
                except subprocess.TimeoutExpired:
                    pass
            raise
        # F3: record fixture errors BEFORE the capture join — the
        # old fixed 60+1s join measured from failure time could time
        # out over a fast fixture failure (round-1: 785 ms life) and
        # mask it as "capture did not exit". The join below only
        # reaps (kept generous from join time: a healthy 60 s
        # capture runs ~64 s wall with startup/drain overrun — DW2
        # — so a remaining-budget join would kill it); the fixture
        # error (the cause) raises first with the join noted.
        fixture_error = None
        try:
            sum_a = _run_fixture(args.tag, name_a, "a.csv")
            sum_b = _run_fixture(args.tag, name_b, "b.csv")
        except LabError as err:
            fixture_error = err
        join_note = "joined"
        try:
            _, _ = capture.communicate(
                timeout=60 + lab.OWNED_REAP_GRACE_S)
        except subprocess.TimeoutExpired:
            capture.kill()
            try:
                capture.wait(timeout=lab.OWNED_REAP_GRACE_S + 5)
            except subprocess.TimeoutExpired:
                join_note = ("join timed out; capture killed, reap "
                             "unverified")
            else:
                join_note = "join timed out; capture reaped"
        if fixture_error is not None:
            raise LabError(f"{fixture_error} (capture {join_note})")
    finally:
        err_file.close()
    if capture.returncode != 3:
        raise LabError("capture rc="
                       f"{capture.returncode}, want 3 (named gaps)")
    cg_a, cg_b = sum_a["cgroup_id"], sum_b["cgroup_id"]
    if cg_a == cg_b:
        raise LabError(f"cgroups not distinct: {cg_a}")
    if sum_a["comm"] != sum_b["comm"]:
        raise LabError(f"comm differs: {sum_a['comm']} vs "
                       f"{sum_b['comm']} (want identical)")
    ledger = {"schema": lab.LEDGER_SCHEMA, "workloads": [
        {"name": "a", "cgroup_id": cg_a,
         "ops": sum_a["ops_total"], "allocs": sum_a.get("allocs", 1)},
        {"name": "b", "cgroup_id": cg_b,
         "ops": sum_b["ops_total"],
         "allocs": sum_b.get("allocs", 1)}]}
    lab.write_ledger(args.out / "two-workloads.ledger.json", ledger)
    folded = fold_cgroup_calls(report)
    reasons = []
    for entry in ledger["workloads"]:
        slot = folded.get(entry["cgroup_id"])
        if slot is None:
            reasons.append(f"cgroup {entry['cgroup_id']} "
                           f"({entry['name']}) unobserved")
            continue
        reasons.extend(lab.reconcile_cgroup(entry["ops"],
                                            slot["enc"],
                                            slot["dec"]))
    if reasons:
        raise LabError(f"oracle mismatch: {reasons}")
    write_receipt(args.out, "two-workloads",
                  {"started_utc": utcnow(), "ledger": ledger,
                   "folded": folded,
                   "fixture_confinement": FIXTURE_CONFINEMENT_NOTE,
                   "verdict": "PASS"})
    print(f"two-workloads PASS: cgroups {cg_a} vs {cg_b} distinct, "
          "both reconciled")
    return 0


def journey_termination(args) -> int:
    name = f"{args.tag}-churn"
    started = run(termination_sleep_argv(args.tag, name), 60)
    if started.returncode != 0:
        raise LabError(f"start {name} failed: "
                       f"{started.stderr.strip()[-300:]}")
    try:
        cg_old = cgroup_id_of_pid(_running_pid(name))
    finally:
        proc = run(["docker", "stop", "-t", "2", name], 30)
    if proc.returncode != 0:
        raise LabError(f"stop {name} failed")
    _wait_container_gone(name)
    started = run(termination_sleep_argv(args.tag, name), 60)
    if started.returncode != 0:
        raise LabError(f"restart {name} failed: "
                       f"{started.stderr.strip()[-300:]}")
    try:
        cg_new = cgroup_id_of_pid(_running_pid(name))
    finally:
        run(["docker", "stop", "-t", "2", name], 30)
    if cg_old == cg_new:
        raise LabError(f"cgroup id reused across recreation: {cg_old}")
    report = args.out / "termination.report.workload-json"
    capture = subprocess.Popen(
        ["kryprobe", "report", "--system", "--duration", "30",
         "--format", "workload-json", "--out", str(report)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        proc = run(fixture_docker_run(
            "--rm", "--name", f"{args.tag}-churn-run",
            fixture_image_tag(args.tag), "skcipher", "4096",
            "10", "2", "/tmp/t.csv"), 150)
        if proc.returncode != 0:
            raise LabError("recreated fixture failed")
        _, _ = capture.communicate(
            timeout=30 + lab.OWNED_REAP_GRACE_S)
    except subprocess.TimeoutExpired as err:
        capture.kill()
        raise LabError("capture did not exit") from err
    folded = fold_cgroup_calls(report)
    if cg_old in folded:
        raise LabError(f"stale cgroup {cg_old} still attributed")
    write_receipt(args.out, "termination",
                  {"started_utc": utcnow(), "cgroup_old": cg_old,
                   "cgroup_new": cg_new,
                   "folded_cgroups": sorted(folded),
                   "fixture_confinement": FIXTURE_CONFINEMENT_NOTE,
                   "verdict": "PASS"})
    print(f"termination PASS: {cg_old} -> {cg_new}, old id absent")
    return 0


FROZEN_UNAVAILABLE = ("no_principal", "helper_refused",
                      "budget_exceeded", "unsupported_environment",
                      "parse_failed")


def _unavailable_case(args, case: str, cmd: list,
                      report_name: str,
                      want_reason: str | None) -> dict:
    report = args.out / report_name
    traffic = subprocess.Popen(
        fixture_docker_run(
            "--rm", "--name", f"{args.tag}-{case}",
            fixture_image_tag(args.tag), "skcipher", "4096", "8",
            "2", "/tmp/u.csv"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        proc = run(cmd + ["--out", str(report)], 120)
    finally:
        try:
            traffic.communicate(
                timeout=60 + lab.OWNED_REAP_GRACE_S)
        except subprocess.TimeoutExpired:
            traffic.kill()
    if proc.returncode != 3:
        raise LabError(f"{case}: rc={proc.returncode}, want 3")
    doc = json.loads(report.read_text())
    status = doc.get("metadata", {}).get("status")
    reason = doc.get("metadata", {}).get("reason")
    if status != "unavailable":
        raise LabError(f"{case}: status={status}, want unavailable")
    if reason not in FROZEN_UNAVAILABLE:
        raise LabError(f"{case}: reason={reason!r} outside the "
                       "frozen vocabulary")
    if want_reason is not None and reason != want_reason:
        raise LabError(f"{case}: reason={reason}, want {want_reason}")
    if not doc.get("contexts"):
        raise LabError(f"{case}: no raw rows (capture blocked?)")
    return {"reason": reason, "rows": len(doc["contexts"])}


def journey_unavailable_metadata(args) -> int:
    base = ["kryprobe", "report", "--system", "--duration", "15",
            "--format", "workload-json"]
    cases = {}
    cases["no-flag"] = _unavailable_case(
        args, "no-flag", base, "unavail-no-flag.workload-json",
        want_reason=None)
    corrupt = args.out / "corrupt-metadata.json"
    corrupt.write_text("{not json")
    cases["corrupt-file"] = _unavailable_case(
        args, "corrupt-file",
        base + ["--workload-metadata", str(corrupt)],
        "unavail-corrupt.workload-json", want_reason=None)
    if os.geteuid() == 0:
        cases["root"] = _unavailable_case(
            args, "root", base + ["--workload-metadata",
                                  str(args.metadata or corrupt)],
            "unavail-root.workload-json",
            want_reason="no_principal")
    else:
        cases["root"] = {"skipped": "needs euid 0 (non-root would "
                                    "serve metadata, not refuse it)"}
    write_receipt(args.out, "unavailable-metadata",
                  {"started_utc": utcnow(), "cases": cases,
                   "fixture_confinement": FIXTURE_CONFINEMENT_NOTE,
                   "verdict": "PASS"})
    print(f"unavailable-metadata PASS: {cases}")
    return 0


def journey_tls(args) -> int:
    """Userspace-TLS negative + kernel-crypto positive control."""
    cg_base = Path("/sys/fs/cgroup")
    server_cg = cg_base / f"{args.tag}-tls-server"
    client_cg = cg_base / f"{args.tag}-tls-client"
    for path in (server_cg, client_cg):
        path.mkdir(exist_ok=True)
    ktls = Path("/proc/net/tls")
    ktls_state = ("absent (kTLS unsupported)"
                  if not ktls.is_file()
                  else ktls.read_text().strip() or "empty")
    server = subprocess.Popen(
        ["openssl", "s_server", "-accept", "18443", "-www",
         "-cert", str(args.tls_cert), "-key", str(args.tls_key)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        (server_cg / "cgroup.procs").write_text(str(server.pid))
        server_cg_id = str(server_cg.stat().st_ino)
        _wait_tcp_listen("127.0.0.1", 18443, 30.0, server)
        report = args.out / "tls.report.workload-json"
        capture = subprocess.Popen(
            ["kryprobe", "report", "--system", "--duration", "20",
             "--format", "workload-json", "--out", str(report)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        try:
            client = subprocess.Popen(
                ["openssl", "s_client", "-connect",
                 "127.0.0.1:18443", "-brief"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            (client_cg / "cgroup.procs").write_text(
                str(client.pid))
            client_cg_id = str(client_cg.stat().st_ino)
            try:
                stdout, stderr = client.communicate(
                    "GET / HTTP/1.0\r\n\r\n",
                    timeout=30 + lab.OWNED_REAP_GRACE_S)
            except subprocess.TimeoutExpired as err:
                client.kill()
                raise LabError("TLS transfer timed out") from err
            if client.returncode != 0:
                alive = "alive" if server.poll() is None \
                    else f"exited={server.poll()}"
                raise LabError("TLS transfer failed "
                               f"(server {alive}): "
                               f"{stderr.strip()[-300:]}")
            positive = _run_fixture(args.tag, f"{args.tag}-pos",
                                    "pos.csv")
            _, _ = capture.communicate(
                timeout=20 + lab.OWNED_REAP_GRACE_S)
        except subprocess.TimeoutExpired as err:
            capture.kill()
            raise LabError("capture did not exit") from err
        if capture.returncode != 3:
            raise LabError("capture rc="
                           f"{capture.returncode}, want 3")
    finally:
        server.terminate()
        try:
            server.wait(timeout=lab.OWNED_REAP_GRACE_S + 5)
        except subprocess.TimeoutExpired:
            server.kill()
    folded = fold_cgroup_calls(report)
    reasons = []
    for cgroup, label in ((server_cg_id, "tls-server"),
                          (client_cg_id, "tls-client")):
        slot = folded.get(cgroup)
        if slot is not None and slot["calls"] != 0:
            reasons.append(f"{label} cgroup shows "
                           f"{slot['calls']} kernel-crypto calls")
    if reasons:
        raise LabError(f"TLS negative failed: {reasons}")
    if not any(slot["calls"] > 0 for slot in folded.values()):
        raise LabError("positive control silent (broken observer?)")
    write_receipt(args.out, "tls",
                  {"started_utc": utcnow(), "ktls": ktls_state,
                   "tls_client_bytes": len(stdout),
                   "positive_ops": positive["ops_total"],
                   "folded_cgroups": sorted(folded),
                   "fixture_confinement": FIXTURE_CONFINEMENT_NOTE,
                   "verdict": "PASS"})
    print("tls PASS: userspace-TLS silent at kernel hooks, "
          "positive control observed")
    return 0


def journey_cleanup(args) -> int:
    before_path = args.out / "inventory-before.json"
    if not before_path.is_file():
        raise LabError("no setup inventory (run setup first)")
    before = json.loads(before_path.read_text())
    names = run(["docker", "ps", "-a", "--format", "{{.Names}}",
                 "--filter", f"name={args.tag}"], 60)
    for name in names.stdout.split():
        proc = run(["docker", "rm", "-f", name], 60)
        if proc.returncode != 0:
            raise LabError(f"rm {name} failed")
    for kind, singular in (("networks", "network"),
                           ("volumes", "volume")):
        listed = run(["docker", singular, "ls", "--format",
                      "{{.Name}}"], 60)
        for name in listed.stdout.split():
            if args.tag in name:
                proc = run(["docker", singular, "rm", name], 60)
                if proc.returncode != 0:
                    raise LabError(f"{singular} rm {name} failed")
    proc = run(["docker", "rmi", fixture_image_tag(args.tag)], 120)
    rmi_note = ("removed" if proc.returncode == 0
                else f"kept: {proc.stderr.strip()[-200:]}")
    for path in Path("/sys/fs/cgroup").glob(f"{args.tag}-*"):
        try:
            path.rmdir()
        except OSError:
            pass
    after = docker_inventory()
    reasons = lab.diff_inventory(before, after, args.tag)
    if reasons:
        raise LabError(f"unrelated resources changed: {reasons}")
    write_receipt(args.out, "cleanup",
                  {"started_utc": utcnow(), "image": rmi_note,
                   "inventory": after, "verdict": "PASS"})
    print("cleanup PASS: owned resources reaped, no unrelated diff")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="docker_lab.py",
        description="Owned-guest Docker labs (freeze G11a).")
    parser.add_argument("--dry-run", action="store_true",
                        help="print planned steps + NOT_RUN, no "
                        "side effects")
    parser.add_argument("--out", type=Path,
                        default=Path("lab-out"),
                        help="receipt/output dir")
    parser.add_argument("--tag", default=lab.LAB_TAG,
                        help="owned-resource name prefix")
    parser.add_argument("--driver", default="",
                        help="M1 driver path (setup/two-workloads)")
    parser.add_argument("--metadata", default="",
                        help="metadata file (unavailable leg)")
    parser.add_argument("--tls-cert", default="",
                        help="TLS server cert (tls leg)")
    parser.add_argument("--tls-key", default="",
                        help="TLS server key (tls leg)")
    parser.add_argument("journey", choices=JOURNEYS)
    args = parser.parse_args(argv)
    if args.dry_run:
        print(f"journey: {args.journey} (owned guest required)")
        for step in DRY_RUN_STEPS[args.journey]:
            print(f"  step: {step}")
        print("NOT_RUN: live guest + Docker needed; no side "
              "effects performed (host disk full, no lease "
              "consumed)")
        return 0
    try:
        if args.journey == "setup":
            return journey_setup(args)
        if args.journey == "two-workloads":
            return journey_two_workloads(args)
        if args.journey == "termination":
            return journey_termination(args)
        if args.journey == "unavailable-metadata":
            return journey_unavailable_metadata(args)
        if args.journey == "tls":
            return journey_tls(args)
        if args.journey == "cleanup":
            return journey_cleanup(args)
    except LabError as err:
        print(f"{args.journey} FAIL: {err}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
