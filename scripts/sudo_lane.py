#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the privileged lane with current Cargo identities and per-body receipts.

Python standard library only. Staged files are presented read-only at Cargo's
compiled-in fixture paths inside a private mount namespace. No source or host
mount is replaced. Build failures, missing bodies and unexplained skips fail.
"""
import argparse
import collections
import contextlib
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


# Reviewed inventory. Additions/removals need an explicit lane decision.
EXPECTED = {
    ("kryprobe-cli", "cli_bpf_e2e"): [
        "selftest_bpf_clean_or_denied", "selftest_token_smoke_needs_root"],
    ("kryprobe-cli", "cli_e2e"): [
        "watch_live_proves_traffic_case", "report_live_proves_json_case",
        "check_live_violation_exit10_case", "check_live_clean_exit3_inconclusive_case"],
    ("kryprobe-cli", "live_k5"): [
        "setcap_roundtrip_unpriv", "attribution_golden_python", "stack_symbol_smoke"],
    ("kryprobe-cli", "live_session"): ["live_capture_proves_session"],
    ("kryprobe-privilege", "bpf_pipeline"): [
        "bpf_pipeline_clean_or_denied", "bpf_pipeline_wide_config_refused"],
    ("kryprobe-privilege", "decoy_pid"): [
        "decoy_tgid_guard_drops_foreign", "decoy_stale_generation_drops"],
    ("kryprobe-privilege", "kcrypto_agg"): [
        "skcipher_exactness", "aead_exactness_and_bad_tag_errors", "hash_points_observed",
        "burst_exactness_near_million", "kcfg_roundtrip_matches_resolver"],
    ("kryprobe-privilege", "kcrypto_attach"): [
        "attach_all_points", "pin_roundtrip_proves_r2_and_cleanup"],
    ("kryprobe-privilege", "kcrypto_canary"): [
        "configured_entry_writes_kcfg_from_resolver", "canary_kcrypto"],
    ("kryprobe-privilege", "kcrypto_driver"): ["driver_e2e_matches_fixture_truth"],
    ("kryprobe-privilege", "kcrypto_snapshot"): [
        "compat_ring_matches_canary_twin", "session_drain_serves_many_windows_with_one_spawn",
        "snapshot_byte_exactness_against_fixture", "captured_row_matches_canonical_layout",
        "drain_start_stop_cycle_leaks_nothing"],
    ("kryprobe-privilege", "kcrypto_tfm_lifecycle"): [
        "host_alloc_capture_assigns_generations", "lifecycle_canary_no_secret_bytes_in_views",
        "host_op_first_seen_carries_selected_driver"],
    ("kryprobe-privilege", "token_plumbing"): [
        "smoke", "token_path_allowlist_denies_unlisted_object"],
    ("kryprobe-testkit", "guest_ledger"): ["guest_ledger_matches_scenario_contract"],
}
LAB_SUITE = ("kryprobe-testkit", "guest_ledger")
LIFECYCLE_SUITE = ("kryprobe-privilege", "kcrypto_tfm_lifecycle")
OBJECTS = ("spine.bpf.o", "kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o")
OBJECT_DIRS = ("stage/kryprobe-bpf", "stage/debug/kryprobe-bpf", "stage/debug/deps/kryprobe-bpf")
NONROOT_BODY = ("kryprobe-cli", "cli_bpf_e2e", "selftest_token_smoke_needs_root")
# This one informational warning does not mean a test body was skipped.
DEV_PIN_WARNING = (
    "kryprobe: BPF object pin check SKIPPED (empty pins in dev build); "
    "set KRYPROBE_PIN_OBJECTS at compile time or KRYPROBE_REQUIRE_PINS=1 to fail closed"
)
_CANCEL_REQUESTED = False


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def cargo_artifacts(text):
    """Only a successful, completed Cargo call can nominate executables."""
    selected = {}
    finished = False
    for line in text.splitlines():
        row = json.loads(line)
        if row.get("reason") == "build-finished":
            if row.get("success") is not True:
                raise ValueError("Cargo build failed")
            finished = True
        if row.get("reason") != "compiler-artifact" or not row.get("executable"):
            continue
        target = row["target"]
        key = (row["package_id"], target["name"], tuple(target["kind"]), row["profile"]["test"])
        identity = {
            "package_id": key[0], "target": key[1], "kind": list(key[2]),
            "test": key[3], "features": sorted(row["features"]),
            "executable": row["executable"],
        }
        if key in selected and selected[key] != identity:
            raise ValueError(f"ambiguous Cargo executable/features for {key}")
        selected[key] = identity
    if not finished or not selected:
        raise ValueError("empty or unfinished Cargo executable inventory")
    return list(selected.values())


def parse_test_list(text):
    names = []
    for line in text.splitlines():
        if line.endswith(": test"):
            names.append(line[:-6])
        elif line.strip() and not re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line):
            raise ValueError(f"unexpected libtest listing: {line!r}")
    return names


def reconcile(observed, expected=EXPECTED):
    actual = {key: sorted(names) for key, names in observed.items() if names}
    wanted = {key: sorted(names) for key, names in expected.items()}
    if actual != wanted:
        differences = {
            str(key): {"expected": wanted.get(key, []), "actual": actual.get(key, [])}
            for key in actual.keys() | wanted.keys() if actual.get(key) != wanted.get(key)
        }
        raise ValueError(f"privileged body inventory drift: {differences}")


def body_verdict(code, output):
    summaries = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; \d+ filtered out; finished in .+$",
        output, re.MULTILINE,
    )
    if code != 0 or summaries != [("1", "0", "0", "0")]:
        return "FAIL"
    if skipped(output):
        return "FAIL"
    return "PASS"


def skipped(output):
    return re.search(r"\b(?:skip(?:ped|ping)?|not_run)\b", output.replace(DEV_PIN_WARNING, ""), re.I) is not None


def lifecycle_verdict(code, output):
    if code == 4 and "kcrypto_fsession_unavailable" in output and "attach type 58 refused (errno 22)" in output:
        return "SUPPORTED_REFUSAL"
    for line in output.splitlines():
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if code in (0, 3) and row == {"audit": "attach", "attached": 7, "expected": 7}:
                return "PASS"
    return "FAIL"


def subreaper():
    # PR_SET_CHILD_SUBREAPER: descendants that double-fork or setsid still
    # become our children when their parent exits, and must be waitpid'd.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def children():
    return {int(pid) for pid in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()}


def reap_owned(proc=None):
    """Hold custody until every child is terminal, including adopted orphans.

    Calls are serial; the runner never owns an unrelated concurrent child.
    Only a current direct child may be signalled, via a pidfd. Repeated
    interrupts cannot break cleanup and release the BPF lease early.
    """
    def defer_cancel(_sig, _frame):
        global _CANCEL_REQUESTED
        _CANCEL_REQUESTED = True
    saved = {sig: signal.signal(sig, defer_cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    start = time.monotonic()
    announced = False
    signalled = set()
    try:
        while True:
            if proc is not None:
                proc.poll()
            for pid in children():
                if proc is not None and pid == proc.pid:
                    continue  # Popen alone owns its wait status.
                with contextlib.suppress(ChildProcessError):
                    os.waitpid(pid, os.WNOHANG)
            owned = children()
            if not owned:
                break
            sig = signal.SIGTERM if time.monotonic() - start < 1 else signal.SIGKILL
            for pid in owned:
                if (pid, sig) in signalled:
                    continue
                with contextlib.suppress(ProcessLookupError):
                    fd = os.pidfd_open(pid)
                    try:
                        if pid in children():
                            signal.pidfd_send_signal(fd, sig)
                            signalled.add((pid, sig))
                    finally:
                        os.close(fd)
            if not announced and time.monotonic() - start > 10:
                print("FAIL sudo-lane: cleanup pending; retaining lane until owned children are reaped", file=sys.stderr, flush=True)
                announced = True
            time.sleep(0.01)
        if proc is not None:
            proc.wait()
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def cancellation():
    def cancelled(sig, _frame):
        global _CANCEL_REQUESTED
        _CANCEL_REQUESTED = True
        raise InterruptedError(f"cancelled by signal {sig}")
    saved = {sig: signal.signal(sig, cancelled) for sig in (signal.SIGTERM, signal.SIGINT)}
    subreaper()
    try:
        yield
    finally:
        reap_owned()
        for sig, handler in saved.items():
            signal.signal(sig, handler)
        if _CANCEL_REQUESTED:
            raise InterruptedError("cancelled; owned descendants reaped")


def watch_parent_pipe():
    # A pipe survives sudo/unshare without allowing a non-root wrapper to
    # signal arbitrary privileged PIDs. EOF, even after wrapper SIGKILL,
    # cancels the executor. Test bodies never inherit this descriptor.
    def watch():
        try:
            while os.read(0, 1):
                pass
        except OSError:
            pass  # lost custody is cancellation, including a hung-up tty
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=watch, daemon=True).start()


def launch_supervised(command):
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, start_new_session=True)
    try:
        return proc.wait()
    finally:
        # EOF requests cooperative privileged cleanup; the wrapper waits for
        # the executor to release custody instead of abandoning its session.
        proc.stdin.close()
        proc.wait()


def run_logged(command, log, timeout, cwd=None, env=None, stderr_path=None):
    """No shell expansion; deadlines and cancellation reap the owned tree."""
    subreaper()
    if _CANCEL_REQUESTED:
        raise InterruptedError("cancelled before next command")
    if children():
        raise ValueError("unexpected child before serial command")
    dump(log.with_suffix(log.suffix + ".command.json"), {
        "argv": [str(part) for part in command], "cwd": str(cwd) if cwd else None,
        "timeout_seconds": timeout,
    })
    start = time.monotonic()
    timed_out, cancelled, leaked = False, False, False
    code = 1
    with contextlib.ExitStack() as stack:
        stream = stack.enter_context(log.open("wb"))
        stderr = stack.enter_context(stderr_path.open("wb")) if stderr_path else subprocess.STDOUT
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stdin=subprocess.DEVNULL,
                                stderr=stderr, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            code = 124
        except BaseException:
            cancelled = True
            raise
        finally:
            leaked = not timed_out and not cancelled and bool(children())
            reap_owned(proc)
            cancelled = cancelled or _CANCEL_REQUESTED
            if leaked and code == 0:
                code = 1
            stream.flush()
            dump(log.with_suffix(log.suffix + ".result.json"), {
                "exit": code, "timed_out": timed_out, "cancelled": cancelled,
                "leaked_children": leaked, "pid": proc.pid, "reaped": True,
                "descendants_reaped": not children(),
                "wall_seconds": time.monotonic() - start, "log_sha256": digest(log),
            })
            if cancelled:
                raise InterruptedError("cancelled; command and descendants reaped")
    return code, timed_out


def source_identity(root):
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root,
    ).split(b"\0")
    hashes = {}
    for raw in paths:
        if raw:
            path = Path(os.fsdecode(raw))
            if (root / path).is_file():
                hashes[str(path)] = digest(root / path)
    return {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "files": hashes,
    }


def prepare(root, out, cargo, traffic_generator):
    traffic_generator = traffic_generator.resolve(strict=True)
    if not traffic_generator.is_file():
        raise ValueError("a regular --traffic-generator file is required")
    before = source_identity(root)
    env = dict(os.environ)
    for key in ("KRYPROBE_PIN_DIGESTS", "KRYPROBE_PIN_OBJECTS", "KRYPROBE_REQUIRE_PINS"):
        env.pop(key, None)
    logs = out / "logs"
    logs.mkdir()
    steps = [
        ("bpf-build", [cargo, "xtask", "build", "--bpf"]),
        ("host-build", [cargo, "build", "--locked", "--workspace", "--message-format=json"]),
        ("test-build", [cargo, "test", "--locked", "--workspace", "--no-run", "--message-format=json"]),
    ]
    artifacts = []
    for name, command in steps:
        print(f"sudo-lane: {name}", flush=True)
        log = logs / f"{name}.log"
        code, _ = run_logged(command, log, 600, cwd=root, env=env,
                             stderr_path=log.with_suffix(".stderr") if name != "bpf-build" else None)
        if code:
            raise ValueError(f"{name} failed ({code}); no privileged execution; see {log}")
        if name != "bpf-build":
            artifacts.extend(cargo_artifacts(log.read_text()))
    metadata = json.loads(subprocess.check_output(
        [cargo, "metadata", "--locked", "--no-deps", "--format-version=1"], cwd=root, env=env,
    ))
    package_names = {package["id"]: package["name"] for package in metadata["packages"]}
    combined = {}
    for row in artifacts:
        if row["package_id"] not in package_names:
            continue
        row["package"] = package_names[row["package_id"]]
        key = (row["package_id"], row["target"], tuple(row["kind"]), row["test"])
        if key in combined and combined[key] != row:
            raise ValueError(f"artifact changed between Cargo invocations: {key}")
        combined[key] = row
    cli_rows = [row for row in combined.values()
                if row["package"] == "kryprobe-cli" and row["target"] == "kryprobe" and not row["test"]]
    if len(cli_rows) != 1:
        raise ValueError("Cargo did not nominate exactly one CLI executable")
    host_debug = Path(cli_rows[0]["executable"]).parent
    # Elevated selftests use ../kryprobe-bpf relative to the CLI, while
    # profile tests also use the debug/deps-local object tiers.
    (host_debug.parent / "kryprobe-bpf").mkdir(parents=True, exist_ok=True)
    observed, selected = {}, []
    for index, row in enumerate(combined.values()):
        if row["test"]:
            log = logs / f"list-{index}.log"
            code, _ = run_logged([row["executable"], "--ignored", "--list", "--format", "terse"], log, 30, cwd=root)
            if code:
                raise ValueError(f"cannot inventory {row['target']}: {log}")
            row["bodies"] = parse_test_list(log.read_text())
            key = (row["package"], row["target"])
            if row["bodies"]:
                if key in observed:
                    raise ValueError(f"ambiguous package/target inventory: {key}")
                observed[key] = row["bodies"]
        else:
            row["bodies"] = []
        if not row["test"] or row["bodies"]:
            selected.append(row)
    reconcile(observed)
    for row in selected:
        original = Path(row["executable"])
        target = out / "stage/debug" / original.relative_to(host_debug)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        target.chmod(0o555)
        row["staged"] = str(target.relative_to(out))
        row["sha256"] = digest(target)
        if row["sha256"] != digest(original):
            raise ValueError(f"artifact changed while staging: {original}")
    for directory in OBJECT_DIRS:
        target = out / directory
        target.mkdir(parents=True, exist_ok=True)
        for name in OBJECTS:
            shutil.copyfile(root / "target/kryprobe-bpf" / name, target / name)
            (target / name).chmod(0o444)
    shutil.copyfile(traffic_generator, out / "stage/kcrypto_gen.py")
    (out / "stage/kcrypto_gen.py").chmod(0o444)
    shutil.copyfile(Path(__file__), out / "stage/runner.py")
    (out / "stage/runner.py").chmod(0o444)
    hashes = {str(path.relative_to(out)): digest(path) for path in (out / "stage").rglob("*") if path.is_file()}
    if before != source_identity(root):
        raise ValueError("source changed during build; discard this inventory")
    # Older fixture paths are compiled relative to the product root even
    # when Cargo uses a custom host target. Prepare this owned mount point.
    (root / "target/debug").mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "kryprobe-privileged-lane/v1", "root": str(root), "out": str(out),
        "source": before, "host_debug": str(host_debug), "artifacts": selected,
        "sha256": hashes, "prepared_kernel": os.uname().release,
        "traffic_generator_source": str(traffic_generator),
        "prepared_uid": os.getuid(), "prepared_gid": os.getgid(),
        "tools": {"python": sys.version,
                  "cargo": subprocess.check_output([cargo, "--version"], cwd=root, env=env, text=True).strip(),
                  "rustc": subprocess.check_output(["rustc", "--version"], cwd=root, env=env, text=True).strip()},
    }
    dump(out / "manifest.json", manifest)
    print(f"sudo-lane: prepared 34 lane bodies (33 root, 1 non-root) and 1 separate lab body at {out}", flush=True)
    return manifest


def verify_stage(out, manifest):
    """Require a bijection between selected payloads and verified regular files."""
    hashes = manifest["sha256"]
    required = {"stage/runner.py", "stage/kcrypto_gen.py"}
    required.update(f"{directory}/{name}" for directory in OBJECT_DIRS for name in OBJECTS)
    identities, paths, suites = set(), set(), set()
    host_debug = Path(manifest["host_debug"])
    if not host_debug.is_absolute():
        raise ValueError("host_debug must be absolute")
    for row in manifest["artifacts"]:
        original = Path(row["executable"])
        relative = original.relative_to(host_debug)
        if ".." in relative.parts or relative == Path("."):
            raise ValueError("executable escapes host_debug")
        staged = str(Path("stage/debug") / relative)
        identity = (row["package_id"], row["target"], tuple(row["kind"]), row["test"])
        suite = (row["package"], row["target"])
        if identity in identities or staged in paths or (row["bodies"] and suite in suites):
            raise ValueError("duplicate prepared artifact identity, path or suite")
        if row["staged"] != staged or row["sha256"] != hashes.get(staged):
            raise ValueError("artifact path/hash disagrees with prepared file map")
        identities.add(identity)
        paths.add(staged)
        if row["bodies"]:
            suites.add(suite)
        required.add(staged)
    if not identities or set(hashes) != required:
        raise ValueError("prepared hash map must cover exactly every selected payload")
    stage = out / "stage"
    actual = {str(path.relative_to(out)) for path in stage.rglob("*") if path.is_symlink() or not path.is_dir()}
    if actual != required:
        raise ValueError("prepared stage contains missing or extra files")
    for relative, expected in hashes.items():
        path = out / relative
        if (not re.fullmatch(r"[0-9a-f]{64}", expected)
                or any(parent.is_symlink() for parent in [path, *path.parents] if parent != out.parent)
                or not path.is_file() or path.resolve(strict=True) != path.absolute()
                or digest(path) != expected):
            raise ValueError(f"staged artifact drift: {relative}")
    for name in OBJECTS:
        if len({hashes[f"{directory}/{name}"] for directory in OBJECT_DIRS}) != 1:
            raise ValueError(f"BPF object copies disagree: {name}")


def bind_readonly(source, target, mounts):
    if not target.exists():
        raise ValueError(f"mount target missing: {target}")
    subprocess.run(["mount", "--bind", str(source), str(target)], check=True)
    mounts.append(target)
    subprocess.run(["mount", "-o", "remount,bind,ro", str(target)], check=True)


def assert_fresh_execution(out):
    for name in ("ownership.json", "results.json", "summary.json", "runtime.json"):
        if (out / name).exists() or (out / name).is_symlink():
            raise ValueError(f"prepared bundle already attempted execution: {name}; use a fresh bundle")


def execute(out, lock_path, parent_mount_ns, calls, manifest_sha256=None):
    if os.geteuid() != 0:
        raise PermissionError("privileged lane needs root or passwordless sudo")
    if not parent_mount_ns or os.readlink("/proc/self/ns/mnt") == parent_mount_ns:
        raise ValueError("refusing mounts outside a fresh private mount namespace")
    assert_fresh_execution(out)
    manifest_bytes = (out / "manifest.json").read_bytes()
    actual_manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha256 is not None and manifest_sha256 != actual_manifest_sha:
        raise ValueError("prepared manifest changed before privileged execution")
    manifest = json.loads(manifest_bytes)
    if manifest["schema"] != "kryprobe-privileged-lane/v1":
        raise ValueError("unknown prepared manifest")
    # O_RDONLY avoids protected_regular restrictions on user-owned /tmp locks.
    lane_fd = os.open(lock_path, os.O_RDONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lane_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lane_fd)
        print(f"NOT_RUN sudo-lane: lock held: {lock_path}", file=sys.stderr)
        return 4
    receipt = {
        "pid": os.getpid(), "start_ticks": Path("/proc/self/stat").read_text().split(") ", 1)[1].split()[19],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "kernel": os.uname().release, "lock": str(lock_path), "out": str(out),
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "manifest_sha256": actual_manifest_sha, "status": "running",
    }
    try:
        with (out / "ownership.json").open("x") as stream:
            stream.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    except BaseException:
        os.close(lane_fd)
        raise
    results, mounts = [], []
    runtime = None
    try:
        # Copy into a root-owned tmpfs whose parent cannot be renamed by
        # the preparer. Verify THAT copy, then mount it read-only. A mutable
        # host staging directory is never an execution source in the lane.
        runtime = Path(tempfile.mkdtemp(prefix="kryprobe-sudo-lane-", dir="/run"))
        runtime.chmod(0o755)
        byte_count = sum((out / relative).stat().st_size for relative in manifest["sha256"])
        if byte_count > 2 * 1024**3:
            raise ValueError("prepared payload exceeds the 2 GiB lane budget")
        subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={byte_count + 256 * 1024**2},mode=0755,nodev",
                        "kryprobe-sudo-lane", str(runtime)], check=True)
        mounts.append(runtime)
        shutil.copytree(out / "stage", runtime / "stage", symlinks=True)
        verify_stage(runtime, manifest)
        for path in (runtime / "stage").rglob("*"):
            path.chmod(0o555 if path.is_dir() or str(path.relative_to(runtime)) in {
                row["staged"] for row in manifest["artifacts"]} else 0o444)
        (runtime / "stage").chmod(0o555)
        bind_readonly(runtime / "stage", runtime / "stage", mounts)
        (runtime / "tmp").mkdir(mode=0o1777)
        (runtime / "tmp").chmod(0o1777)
        dump(out / "runtime.json", {"root_owned_copy": str(runtime), "bytes": byte_count,
                                   "sha256": manifest["sha256"]})
        root = Path(manifest["root"])
        for target in dict.fromkeys([Path(manifest["host_debug"]), root / "target/debug"]):
            bind_readonly(runtime / "stage/debug", target, mounts)
        for target in dict.fromkeys([Path(manifest["host_debug"]).parent / "kryprobe-bpf",
                                     root / "target/kryprobe-bpf"]):
            bind_readonly(runtime / "stage/kryprobe-bpf", target, mounts)
        env = dict(os.environ, TMPDIR=str(runtime / "tmp"),
                   KRYPROBE_TEST_TRAFFIC_GENERATOR=str(runtime / "stage/kcrypto_gen.py"))
        cli = runtime / "stage/debug/kryprobe"
        logs = out / "logs"
        observed = {}
        for index, row in enumerate(manifest["artifacts"]):
            if not row["test"]:
                continue
            log = logs / f"runtime-list-{index}.log"
            code, _ = run_logged([str(runtime / row["staged"]), "--ignored", "--list", "--format", "terse"],
                                 log, 30, cwd=root, env=env)
            bodies = parse_test_list(log.read_text()) if code == 0 else []
            if bodies != row["bodies"]:
                raise ValueError(f"runtime body inventory changed: {row['target']}")
            observed[(row["package"], row["target"])] = bodies
        reconcile(observed)
        log = logs / "lifecycle-support.log"
        code, _ = run_logged([str(cli), "report", "--system", "--kcrypto-profile", "request-lifecycle",
                              "--duration", "1", "--format", "json"], log, 30, cwd=Path("/"), env=env)
        support = lifecycle_verdict(code, log.read_text())
        results.append({"test": "lifecycle-support", "status": support, "log": str(log.relative_to(out))})
        for row in manifest["artifacts"]:
            key = (row["package"], row["target"])
            for body in row["bodies"]:
                result = {"package": key[0], "target": key[1], "test": body,
                          "features": row["features"], "executable_sha256": row["sha256"]}
                if key == LAB_SUITE:
                    result.update(status="OTHER_LANE", reason="requires scenario ledger; run scripts/kcrypto-lab.py")
                elif key == LIFECYCLE_SUITE and support != "PASS":
                    result.update(status=support, reason="see lifecycle-support.log; body not executed")
                else:
                    log = logs / f"{key[0]}-{key[1]}-{body}.log"
                    command = [str(runtime / row["staged"]), "--ignored", "--exact", body,
                               "--nocapture", "--test-threads=1", "--format", "pretty"]
                    uid, gid = 0, 0
                    if (*key, body) == NONROOT_BODY:
                        uid = manifest["prepared_uid"] or 65534
                        gid = manifest["prepared_gid"] or 65534
                        command = ["setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
                                   "--inh-caps=-all", "--ambient-caps=-all", "--", sys.executable, "-I", "-c",
                                   "import os,sys,json; "
                                   f"assert os.geteuid()=={uid} and os.getegid()=={gid}; "
                                   "print(json.dumps({'runner_identity':{'euid':os.geteuid(),'egid':os.getegid()}}),flush=True); "
                                   "os.execv(sys.argv[1],sys.argv[1:])", *command]
                    code, timed_out = run_logged(command, log, 180, cwd=root, env=env)
                    result.update(status=body_verdict(code, log.read_text(errors="replace")),
                                  exit=code, timed_out=timed_out, euid=uid, egid=gid, log=str(log.relative_to(out)))
                results.append(result)
                dump(out / "results.json", results)
                print(f"sudo-lane: {key[0]}/{key[1]}::{body}: {result['status']}", flush=True)
        for name, args in [("selftest-bpf", ["selftest", "bpf", "--calls", str(calls)]),
                           ("selftest-token-smoke", ["selftest", "token-smoke"])]:
            log = logs / f"{name}.log"
            code, timed_out = run_logged([str(cli), *args], log, 180, cwd=root, env=env)
            output = log.read_text(errors="replace")
            status = "PASS" if code == 0 and not skipped(output) else "FAIL"
            results.append({"test": name, "status": status, "exit": code,
                            "timed_out": timed_out, "log": str(log.relative_to(out))})
        verify_stage(runtime, manifest)
        dump(out / "results.json", results)
        counts = dict(collections.Counter(result["status"] for result in results))
        code = 1 if counts.get("FAIL") else (4 if counts.get("SUPPORTED_REFUSAL") else 0)
        receipt.update(status="finished", exit=code, counts=counts, staged_hashes_unchanged=True)
    except BaseException as error:
        receipt.update(status="failed", exit=1, error=str(error))
        dump(out / "summary.json", {"exit": 1, "error": str(error), "complete": False})
        raise
    finally:
        # Children must be reaped before mounts or the exclusive lock go.
        reap_owned()
        if _CANCEL_REQUESTED:
            receipt.update(status="failed", exit=1, error="cancelled")
            dump(out / "summary.json", {"exit": 1, "complete": False, "error": "cancelled"})
        cleanup_errors = []
        for target in reversed(mounts):
            cleanup = subprocess.run(["umount", str(target)], capture_output=True, text=True)
            if cleanup.returncode:
                cleanup_errors.append({"target": str(target), "stderr": cleanup.stderr})
        if runtime is not None and not cleanup_errors:
            runtime.rmdir()
        if cleanup_errors:
            receipt.update(status="failed", exit=1, cleanup_errors=cleanup_errors)
            dump(out / "summary.json", {"exit": 1, "complete": False, "cleanup_errors": cleanup_errors})
        receipt["children_reaped"] = not children()
        receipt["owned_mounts_removed"] = not cleanup_errors
        receipt["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        dump(out / "ownership.json", receipt)
        os.close(lane_fd)
        if cleanup_errors:
            raise ValueError(f"owned mount cleanup failed: {cleanup_errors}")
        if _CANCEL_REQUESTED:
            raise InterruptedError("cancelled; lane cleanup complete")
    # A complete summary is published only after owned processes and
    # mounts are gone. An interrupted cleanup cannot leave a green receipt.
    dump(out / "summary.json", {"counts": counts, "exit": code, "expected_bodies": 34,
                                "root_bodies": 33, "nonroot_bodies": 1, "complete": True})
    print(f"sudo-lane: {counts}; exit {code}; evidence {out}", flush=True)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="new owned evidence/staging directory")
    parser.add_argument("--prepare-only", action="store_true", help="build and seal; no privileged tests")
    parser.add_argument("--run-prepared", type=Path, help="run a prepared directory, including in an owned VM")
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("--traffic-generator", type=Path, default=Path("/tmp/kcrypto_gen.py"))
    parser.add_argument("--lock", type=Path, default=Path(os.environ.get("KRYPROBE_LANE_LOCK", "/tmp/kryprobe-bpf-lane.lock")))
    parser.add_argument("--calls", type=int, default=int(os.environ.get("KRYPROBE_BPF_CALLS", "20000")))
    parser.add_argument("--execute", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--parent-mount-ns", help=argparse.SUPPRESS)
    parser.add_argument("--manifest-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--watch-parent-pipe", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.calls <= 0:
        parser.error("--calls must be positive")
    if args.execute:
        if not args.manifest_sha256 or not args.watch_parent_pipe:
            parser.error("internal execution requires a manifest digest and parent pipe")
        watch_parent_pipe()
        return execute(args.execute.resolve(strict=True), args.lock, args.parent_mount_ns, args.calls,
                       args.manifest_sha256)
    root = Path(__file__).resolve().parent.parent
    if args.run_prepared:
        out = args.run_prepared.resolve(strict=True)
        assert_fresh_execution(out)
        manifest = json.loads((out / "manifest.json").read_text())
    else:
        if args.out:
            out = args.out.resolve()
            out.mkdir(mode=0o755)  # never reuse or clobber an earlier receipt
        else:
            out = Path(tempfile.mkdtemp(prefix="kryprobe-sudo-lane-"))
        (root / "target").mkdir(exist_ok=True)
        # Same lock as release packaging: neither consumer may repin or
        # copy a BPF object while the other is rewriting it.
        with (root / "target/.build-release.lock").open("a") as build_lock:
            fcntl.flock(build_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            manifest = prepare(root, out, args.cargo, args.traffic_generator)
    if args.prepare_only:
        verify_stage(out, manifest)
        return 0
    manifest_bytes = (out / "manifest.json").read_bytes()
    if json.loads(manifest_bytes) != manifest:
        raise ValueError("prepared manifest changed before launch")
    # Freeze the bootstrap bytes in argv before privilege elevation. The
    # interpreter does not reopen a host-mutable script after this check.
    # The child verifies the full root-owned copy once, and again at exit.
    runner = out / "stage/runner.py"
    runner_bytes = runner.read_bytes()
    if hashlib.sha256(runner_bytes).hexdigest() != manifest["sha256"]["stage/runner.py"]:
        raise ValueError("prepared runner changed")
    bootstrap = f"__file__={str(runner)!r}; exec(compile({runner_bytes!r},__file__,'exec'))"
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    command = [*sudo, "unshare", "--mount", "--propagation", "private", "--", sys.executable, "-I", "-c", bootstrap,
               "--execute", str(out), "--lock", str(args.lock), "--watch-parent-pipe",
               "--manifest-sha256", hashlib.sha256(manifest_bytes).hexdigest(), "--calls", str(args.calls),
               "--parent-mount-ns", os.readlink("/proc/self/ns/mnt")]
    return launch_supervised(command)


if __name__ == "__main__":
    try:
        with cancellation():
            sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL sudo-lane: {error}", file=sys.stderr)
        sys.exit(1)
