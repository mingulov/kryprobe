#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the privileged lane with current Cargo identities and per-body receipts.

Python standard library only. Staged files are presented read-only at Cargo's
compiled-in fixture paths inside a private mount namespace. No source or host
mount is replaced. Build failures, missing bodies and unexplained skips fail.
Skips are accepted only from the documented env-gate allowlist
(ENV_GATED_BODIES), each with its exact loud marker; those bodies report
ENV_GATED_SKIP (recorded in results/summary counts, never silent).
"""
import argparse
import collections
import contextlib
import ctypes
import datetime
import errno
import fcntl
import functools
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time


# Reviewed inventory. Additions/removals need an explicit lane decision.
EXPECTED = {
    ("kryprobe-cli", "cli_bpf_e2e"): [
        "selftest_bpf_clean_partial_or_denied", "selftest_token_smoke_needs_root"],
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
    ("kryprobe-privilege", "kcrypto_ctx"): [
        "ctx_first_over_capacity_is_exact",
        "ctx_map_full_refuse_new_is_exact",
        "fence_close_freezes_our_ctx_rows",
        "same_process_cgroup_migration_splits_counts",
        "second_observer_sees_same_ctx_rows",
    ],
    ("kryprobe-privilege", "kcrypto_driver"): ["driver_e2e_matches_fixture_truth"],
    ("kryprobe-privilege", "kcrypto_snapshot"): [
        "compat_ring_matches_canary_twin", "session_drain_serves_many_windows_with_one_spawn",
        "snapshot_byte_exactness_against_fixture", "captured_row_matches_canonical_layout",
        "drain_start_stop_cycle_leaks_nothing"],
    ("kryprobe-privilege", "kcrypto_requests"): [
        "guest_below_floor_refuses_typed", "guest_enokey_leaves_provider_unentered",
        "guest_sync_meta_matches_fixture_truth"],
    ("kryprobe-privilege", "kcrypto_tfm_lifecycle"): [
        "host_alloc_capture_assigns_generations", "lifecycle_canary_no_secret_bytes_in_views",
        "host_op_first_seen_carries_selected_driver"],
    # M1 Stage 1: the hammer oracle lives in the lib unit tests
    # (backend internals); inventoried exactly like suites.
    ("kryprobe-privilege", "kryprobe_privilege"): [
        "kcrypto_backend::tests::finish_session_quiescent_under_hammer_freezes_terminal",
    ],
    ("kryprobe-privilege", "token_plumbing"): [
        "smoke", "token_path_allowlist_denies_unlisted_object"],
    ("kryprobe-testkit", "guest_ledger"): ["guest_ledger_matches_scenario_contract"],
}
LAB_SUITE = ("kryprobe-testkit", "guest_ledger")
# P3r narrowed (c): vng-only guest bodies are inventoried here (complete
# accounting — reconcile stays exact) but routed to OTHER_LANE, never
# executed on the host; the vng-lane guest cells run them instead.
VNG_SUITE = ("kryprobe-privilege", "kcrypto_requests")
LIFECYCLE_SUITE = ("kryprobe-privilege", "kcrypto_tfm_lifecycle")
OBJECTS = ("spine.bpf.o", "kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o")
OBJECT_DIRS = ("stage/kryprobe-bpf", "stage/debug/kryprobe-bpf", "stage/debug/deps/kryprobe-bpf")
NONROOT_BODY = ("kryprobe-cli", "cli_bpf_e2e", "selftest_token_smoke_needs_root")
# The cargo-test path that runs `selftest bpf --calls`: accounted
# partials accepted inside it must re-verify from its log (fail closed
# on divergence) and land in summary.json like the direct body.
SELFTEST_BPF_E2E = ("kryprobe-cli", "cli_bpf_e2e", "selftest_bpf_clean_partial_or_denied")
# This one informational warning does not mean a test body was skipped.
DEV_PIN_WARNING = (
    "kryprobe: BPF object pin check SKIPPED (empty pins in dev build); "
    "set KRYPROBE_PIN_OBJECTS at compile time or KRYPROBE_REQUIRE_PINS=1 to fail closed"
)
# F-C1: request-lifecycle manifest (P5): 10 required fsession sites +
# 2 optional fentry callbacks, attach-if-present, never gating
# (`profile.rs::manifest(RequestLifecycle)`). Bring-up is
# all-or-nothing on the required set, so a live sensor reports
# attached in 10..12 against expected 12.
LIFECYCLE_REQUIRED = 10
LIFECYCLE_CALLBACKS = 2
LIFECYCLE_EXPECTED = LIFECYCLE_REQUIRED + LIFECYCLE_CALLBACKS
# F-C3: environment-gated bodies. Each entry maps (package, target,
# body) to the prerequisite token the body's loud env-gate marker
# must name. ONLY these bodies may skip, and ONLY by printing the
# exact `SKIP (env-gated): <body> requires <prereq>` marker (with the
# doc pointer); any other skip text, on any body, still FAILs.
# Prerequisites live in docs/lane-environment.md; the lane never
# installs them (no shared-machine mutation).
ENV_GATED_BODIES = {
    ("kryprobe-cli", "live_k5", "attribution_golden_python"): "bpftrace",
    ("kryprobe-cli", "live_k5", "setcap_roundtrip_unpriv"): "nogroup",
}
ENV_GATE_DOC = "docs/lane-environment.md"
_CANCEL_REQUESTED = False
# Evidence repair for a cancel that lands after execute's last
# checkpoint: set by execute just before the complete summary
# is published, consumed (take-and-clear) by cancellation's
# finally. Repairs only an existing complete:true summary —
# never a failure record — so running it on a raise path is
# a no-op read, never a root-cause clobber.
_CANCELLATION_REPAIR = None
# Outer-custody outcome for the repair above: set by
# cancellation's finally before the repair runs (every
# run sets it fresh), reset by execute on entry. The
# repair reads it to invalidate the published custody
# claim and name the failure; direct repair callers see
# False (the cancel-only text), as before.
_CANCELLATION_REAP_FAILED = False
# Wait slice for cancel polling: run_logged and
# launch_supervised re-check the flag this often, so a
# flag-only cancel takes effect within ~a slice instead of
# at child exit. Well under the 5 s custody deadlines.
_WAIT_SLICE = 0.25


def _text_sink(fd):
    """UTF-8 text stream owning `fd`, with ownership-safe setup.

    io.FileIO never owns the descriptor on setup failure
    (verified: a failed FileIO leaves the fd open), so the
    raw fd is closed in that case; later-stage failures close
    the raw OBJECT, which is idempotent-safe — unlike closing
    the fd number twice, it can never touch a reused number.
    Matches os.fdopen(fd, "w", encoding="utf-8") semantics.
    """
    try:
        raw = io.FileIO(fd, "w")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        return io.TextIOWrapper(io.BufferedWriter(raw), encoding="utf-8")
    except BaseException:
        try:
            raw.close()
        except OSError:
            pass
        raise


def dump(path, value):
    """Atomic JSON write (temp + rename): readers see the old or the new
    file, never a partial one. Atomicity, not fsync durability. The
    temp name is random-exclusive (mkstemp), so a planted symlink in
    a reused prepared directory is never followed. Published files
    are world-readable (mkstemp's 0600 is widened before the
    rename): the CI summary check opens them unprivileged. A
    failed write or replace removes the temp and raises the
    original error; cleanup never masks it and leaks nothing.
    A write/flush error stays primary when the close retry
    fails too (the close error is kept as its context, except
    that KeyboardInterrupt/SystemExit from close propagate
    immediately); a close-only failure propagates. The body
    runs shielded, so the lane's own cancel signal only sets
    _CANCEL_REQUESTED (acted on at the caller's checkpoint)
    and never surfaces here as InterruptedError."""
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    # The whole body runs deferred: small bounded regfile writes
    # never block, so no async window can strand the temp or fd.
    with _deferred_cancel():
        fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                                   dir=str(path.parent))
        try:
            os.fchmod(fd, 0o644)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            stream = _text_sink(fd)
        except BaseException:
            # _text_sink owns all its failures (the descriptor is
            # already closed): closing the number again could hit
            # a reused fd, so only the temp goes.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            try:
                stream.write(text)
                stream.flush()
            except BaseException as write_error:
                try:
                    stream.close()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException as close_error:
                    write_error.__context__ = close_error
                raise
            else:
                stream.close()
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _publish_json(path, value):
    """dump() that reports instead of raising.

    Cleanup-time publishing must never abort the unmount /
    ownership sequence: a hostile directory planted at the
    target name, or a full disk, returns the error string so
    the caller can record it and proceed. Success returns None.
    OSError is contained — including the lane's own
    InterruptedError cancel signal, which stays effective
    through _CANCEL_REQUESTED at the next checkpoint.
    Anything else (programming errors, genuine termination)
    still propagates.
    """
    try:
        dump(path, value)
    except OSError as error:
        return str(error)
    return None


def _guarded_publish(path, value, publish_errors, deferred):
    """_publish_json that also defers non-OSError escapes past cleanup.

    OSError (planted names, full disk) is recorded; anything else
    (allocation failure class — genuine interrupts arrive as
    OSError or are deferred by the caller) is queued for a gated
    re-raise after unmounts, ownership, and lock close complete.
    """
    try:
        error = _publish_json(path, value)
    except BaseException as error:
        deferred.append(error)
    else:
        if error is not None:
            publish_errors.append(error)


def digest(path):
    """sha256 of a regular file, honoring cancellation.

    The leaf opens O_NOFOLLOW|O_NONBLOCK and is
    fstat-pinned regular: a swapped-in symlink refuses
    and a swapped-in FIFO fails closed instead of
    hanging the lane uninterruptibly on open. Only the
    leaf is pinned — callers resolve through
    caller-owned (prepare) or root-owned (execute)
    parents.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(
                f"refusing non-regular digest input: {path}")
        sha = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                if _CANCEL_REQUESTED:
                    raise InterruptedError("cancelled during digest")
                sha.update(chunk)
        return sha.hexdigest()
    finally:
        os.close(fd)


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


def env_gate_marker(key, body):
    """The loud env-gate marker an allowlisted body must print, or None."""
    if key is None or body is None:
        return None
    prereq = ENV_GATED_BODIES.get((*key, body))
    if prereq is None:
        return None
    return f"SKIP (env-gated): {body} requires {prereq}"


def body_verdict(code, output, key=None, body=None):
    summaries = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; \d+ filtered out; finished in .+$",
        output, re.MULTILINE,
    )
    if code != 0 or summaries != [("1", "0", "0", "0")]:
        return "FAIL"
    if not skipped(output):
        return "PASS"
    marker = env_gate_marker(key, body)
    # Substring match: libtest pretty framing prefixes the body's line
    # ("test <body> ... <marker>"), so the marker rarely starts a line.
    # Everything besides the exact marker must still be skip-free.
    if marker is None or marker not in output:
        return "FAIL"
    if skipped(output.replace(marker, "")):
        return "FAIL"
    return "ENV_GATED_SKIP"


def skipped(output):
    return re.search(r"\b(?:skip(?:ped|ping)?|not_run)\b", output.replace(DEV_PIN_WARNING, ""), re.I) is not None


_PARTIAL_LINE_RE = re.compile(
    r"^selftest bpf: partial \((\d+) missing; ring=(\d+) drop=(\d+) trunc=(\d+) queue=(\d+)\)$",
    re.ASCII,
)
_ENTRIES_LINE_RE = re.compile(
    r"^selftest bpf: entries=(\d+) returns=(\d+) received=(\d+)"
    r" ring=(\d+) drop=(\d+) trunc=(\d+) queue=(\d+)$",
    re.ASCII,
)
_U64MAX = (1 << 64) - 1
# The Rust e2e body announces accepted partials with this prefix and
# echoes the child output for lane re-verification (cli_bpf_e2e.rs).
E2E_PARTIAL_ANNOUNCEMENT = "selftest bpf: accounted partial"


def _u64(text):
    """Decimal value ignoring leading zeros (aligns with Rust's u64 parse)."""
    return int(text.lstrip("0") or "0")


def _reject_constant(value):
    raise ValueError(f"non-JSON constant: {value}")


def _no_dup_object(pairs):
    """JSONObject decoder: duplicate keys reject (last-wins smuggles)."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key: {key}")
        obj[key] = value
    return obj


def _strict_int(text):
    # "-0" parses as int 0 here but float in serde: reject the token.
    # Otherwise integers are restricted to i64/u64 — intentionally
    # stricter than serde, which floats overflows and errors only
    # past f64::MAX.
    if text == "-0":
        raise ValueError("negative zero")
    value = int(text)
    if value < -(1 << 63) or value > _U64MAX:
        raise ValueError(f"integer out of range: {text[:24]}")
    return value


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"non-finite float: {text}")
    return value


def _depth_exceeds(value, limit=127):
    """More than limit nested containers (serde allows 127: probed
    127-ok/128-err). Scalars add no depth. Iterative, never raises."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if not isinstance(item, (list, dict)):
            continue
        if depth >= limit:
            return True
        children = item.values() if isinstance(item, dict) else item
        stack.extend((child, depth + 1) for child in children)
    return False


def _has_surrogate(value):
    """Lone UTF-16 surrogates (serde rejects them; valid pairs decode clean).

    Iterative: deeply nested input must reject, never raise.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                return True
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
    return False


def partial_receipt(output, calls):
    """Accounted-partial receipt for a `selftest bpf --calls` log, or None.

    Pressure-only receipts (P7/T12): the ring/queue shortfall is not a
    defect, but drop/trunc are anomaly buckets (spine.rs: pre-arm
    hits, generation/TGID mismatch, wide CONFIG) and never accepted.
    The printed `partial (N missing; ...)` number is arm-dependent
    (the loss ledger excludes queue drops, so on the ledger-Partial
    arm it is the post-receipt remainder) and proves nothing alone;
    only its shape, u64 range, and agreement with the entries line
    are checked. The receipt re-derives full accounting from the
    entries line against the invoked `calls`: every generated record
    (2·calls) is delivered or carries a pressure receipt, neither
    kind over-counts, both kinds were observed, and the session
    record agrees (PARTIAL, fixture exit 0). Candidate lines are
    counted by reserved prefix first, so malformed extras reject
    instead of being ignored. Shared JSON policy with the Rust arm:
    exactly one session_end in the whole stream (whitespace-prefixed
    candidates included, raw spelling counted too), no duplicate
    keys, strict constants (no NaN/Infinity), finite floats, no
    lone surrogates, nesting capped at 127 containers like serde,
    object payload, exact field types — plus two rules
    intentionally stricter than serde, which floats -0 and
    overflows: no negative zero, i64/u64 integers. Any '{'
    outside a parsed candidate rejects
    (unsupported framing). Numbers ignore leading zeros like
    Rust's u64 parse. Never raises on malformed input.
    """
    if "\r" in output or "\ufffd" in output:
        return None
    if not isinstance(calls, int) or not 0 < calls <= _U64MAX // 2:
        return None
    if output.count('"session_end"') != 1:
        return None
    lines = output.split("\n")
    if [line for line in lines if line.startswith("reconcile:")] != ["reconcile: partial"]:
        return None
    partials = [line for line in lines if line.startswith("selftest bpf: partial (")]
    if len(partials) != 1:
        return None
    match = _PARTIAL_LINE_RE.match(partials[0])
    if not match:
        return None
    found = [line for line in lines if line.startswith("selftest bpf: entries=")]
    if len(found) != 1:
        return None
    counts = _ENTRIES_LINE_RE.match(found[0])
    if not counts:
        return None
    try:
        printed = [_u64(v) for v in match.groups()]
        entries, returns, received, ring, drop, trunc, queue = (
            _u64(v) for v in counts.groups())
    except ValueError:
        return None
    if any(v > _U64MAX for v in printed):
        return None
    if printed[1:] != [ring, drop, trunc, queue]:
        return None
    if drop != 0 or trunc != 0:
        return None
    if entries + returns != received:
        return None
    if entries > calls or returns > calls or entries == 0 or returns == 0:
        return None
    if received + ring + drop + trunc + queue != 2 * calls:
        return None
    if ring + queue == 0:
        return None
    ends = []
    for line in lines:
        candidate = line.lstrip(" \t")
        if not candidate.startswith("{"):
            # A brace outside a parsed candidate: a record under
            # unsupported framing (exotic prefix, mid-line object,
            # spaced opener) that the scan cannot see, so the raw
            # spelling count cannot be trusted — reject instead of
            # ignoring. Real logs only carry '{' inside candidates.
            if "{" in line:
                return None
            continue
        try:
            record = json.loads(
                candidate,
                parse_constant=_reject_constant,
                parse_int=_strict_int,
                parse_float=_finite_float,
                object_pairs_hook=_no_dup_object,
            )
        except (ValueError, RecursionError):
            return None
        if (not isinstance(record, dict) or _has_surrogate(record)
                or _depth_exceeds(record)):
            return None
        if record.get("kind") == "session_end":
            ends.append(record)
    if len(ends) != 1:
        return None
    payload = ends[0].get("payload")
    if not isinstance(payload, dict):
        return None
    if payload.get("verdict") != "PARTIAL":
        return None
    code = payload.get("child_exit_code")
    if type(code) is not int or code != 0:
        return None
    if "child_signal" not in payload or payload["child_signal"] is not None:
        return None
    return {"exit": 3, "calls": calls, "missing": 2 * calls - received,
            "entries": entries, "returns": returns, "received": received,
            "ring": ring, "drop": drop, "trunc": trunc, "queue": queue}


def e2e_partial_guard(output, calls, status):
    """(status, receipt-or-None) for the SELFTEST_BPF_E2E cargo body log.

    The Rust test announces accepted partials; the lane must receipt
    them from the echoed child output — a missing/truncated echo or
    unparseable accounting fails closed. Only PASS bodies contribute
    receipts, so `accepted_partials` never names a failed body.
    """
    claimed = E2E_PARTIAL_ANNOUNCEMENT in output or "reconcile: partial" in output
    if not claimed:
        return status, None
    receipt = partial_receipt(output, calls)
    if receipt is None or status != "PASS":
        return "FAIL", None
    return status, receipt


def summarize_partials(results):
    """`accepted_partials` entries for summary.json from body results."""
    partials = []
    for row in results:
        accepted = row.get("accepted_partial")
        if accepted is None:
            continue
        ident = row["test"] if "package" not in row else (
            f"{row['package']}/{row['target']}::{row['test']}")
        partials.append({"test": ident, **accepted})
    return partials


_COMMITTED_READ_CAP = 1024 * 1024


def _exact_json_equal(a, b):
    """Deep equality with exact scalar types.

    Plain == conflates True/1/1.0 and False/0, so a loosened
    persisted row would validate. Genuine rows roundtrip
    losslessly (dict order aside), so strictness rejects only
    foreign content. NaN never validates (and rows never hold it).
    """
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(
            _exact_json_equal(a[key], b[key]) for key in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(
            _exact_json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return False
    return type(a) is type(b) and a == b


def committed_prefix(out, results):
    """Prefix of `results` atomically committed to results.json on disk.

    Crash truth for incomplete summaries: the file is written
    atomically from ever-longer prefixes of the append-only results
    list, so its row count — read at summary time, after the dust
    settles — is immune to interruption between append and persist.
    Missing/unreadable/non-list file: no rows are claimed. The read
    is size-bounded and never raises on file content: the
    descriptor is opened O_NOFOLLOW (a planted symlink claims
    nothing), non-regular files are refused without blocking on
    FIFOs, at most cap+1 bytes are read, and oversize input is
    rejected outright — never parsed as a truncated prefix. Only
    the row COUNT comes from disk, so persisted rows must equal
    the in-memory prefix exactly (length, content, scalar types;
    duplicate keys reject): a foreign list claims nothing.
    Decoded allocation is unbounded by the byte cap (1MB of
    [{},{}...] is ~25MB), so a recoverable MemoryError is caught
    too — this function holds no state, so [] stays fail-closed
    and cleanup still proceeds. (Allocation failure while opening
    the fixed pathname is outside this contract: nothing
    input-driven can trigger it.) The directory stays writable
    by the preparer for the whole run.
    """
    # The whole body runs shielded (like _exclusive_sink): even
    # the return-to-assignment step after os.open is covered, so
    # no signal can strand the descriptor between acquisition
    # and ownership. A signal here defers to the flag, acted on
    # at the caller's checkpoint; the except below only sees
    # genuine I/O and parse failures.
    fd = None
    with _deferred_cancel():
        try:
            fd = os.open(out / "results.json",
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return []
            chunks = []
            remaining = _COMMITTED_READ_CAP + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _COMMITTED_READ_CAP:
                return []
            committed = json.loads(raw, object_pairs_hook=_no_dup_object)
            if (isinstance(committed, list) and len(committed) <= len(results)
                    and _exact_json_equal(committed, results[:len(committed)])):
                return results[:len(committed)]
        except (OSError, ValueError, RecursionError, MemoryError):
            pass
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return []


def selftest_verdict(code, output, name, calls):
    """Verdict for the `selftest-*` support bodies.

    Exit 0 passes when skip-free. `selftest-bpf` exit 3 passes only for
    a fully-accounted partial (P7/T12: receipted coverage gaps are not
    defects): `partial_receipt` must re-derive full accounting from
    the entries line against `calls`. Everything else — defects,
    marker/exit mismatches, unparsable logs, skips at any exit, other
    bodies — fails closed.
    """
    if skipped(output):
        return "FAIL"
    if code == 0:
        return "PASS"
    if code == 3 and name == "selftest-bpf" and partial_receipt(output, calls):
        return "PASS"
    return "FAIL"


def normalize_leak(code, leaked):
    """A leaked child is an execution defect at any exit code."""
    return 1 if leaked else code


def decode_body_log(data):
    """Body log text with raw newlines preserved (a CR must stay visible).

    UTF-8 is explicit: the U+FFFD guard must not depend on root's locale.
    bytes.decode performs no newline translation (the newline="" half).
    """
    return data.decode("utf-8", errors="replace")


def lifecycle_verdict(code, output):
    if code == 4 and "kcrypto_fsession_unavailable" in output and "attach type 58 refused (errno 22)" in output:
        return "SUPPORTED_REFUSAL"
    for line in output.splitlines():
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            attached = row.get("attached")
            if (code in (0, 3) and set(row) == {"audit", "attached", "expected"}
                    and row["audit"] == "attach" and row["expected"] == LIFECYCLE_EXPECTED
                    and type(attached) is int
                    and LIFECYCLE_REQUIRED <= attached <= LIFECYCLE_EXPECTED):
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
    # The reaping loop runs under the shared shield (mask-blocked
    # install/restore): a signal mid-loop defers to the flag,
    # which the caller acts on at its checkpoint.
    start = time.monotonic()
    announced = False
    signalled = set()
    with _deferred_cancel():
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
                _say_err("FAIL sudo-lane: cleanup pending; retaining lane until owned children are reaped")
                announced = True
            time.sleep(0.01)
        if proc is not None:
            proc.wait()


@contextlib.contextmanager
def _deferred_cancel():
    """Defer SIGTERM/SIGINT to the flag across a non-interruptible window.

    A raising handler firing between fd acquisition and ownership
    transfer would leak the descriptor; shielding publishes and
    the cleanup sequence lets them complete, with cancellation
    taking effect at the next checkpoint via _CANCEL_REQUESTED.
    Handler install and restore run under a blocked signal mask
    (a signal between the two installs would otherwise escape
    the shield with a half-installed table); arrivals during
    the swap pend and are deferred on unmask. The old mask is
    saved/restored so nesting is safe — though install windows
    never actually nest (each completes before any other code
    runs). Off the main thread this is a plain yield: signals
    only deliver to the main thread, so no window exists
    elsewhere (and signal.signal would raise there).
    """
    if threading.get_ident() != threading.main_thread().ident:
        yield
        return
    def defer(_sig, _frame):
        global _CANCEL_REQUESTED
        _CANCEL_REQUESTED = True
    sigs = (signal.SIGTERM, signal.SIGINT)
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
    saved = {}
    try:
        for sig in sigs:
            saved[sig] = signal.signal(sig, defer)
    except BaseException:
        for sig, handler in saved.items():
            signal.signal(sig, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        raise
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    try:
        yield
    finally:
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
        try:
            for sig, handler in saved.items():
                signal.signal(sig, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def _say(message):
    """Diagnostic print contained against stream failure.

    The stream is captured once: printing and
    discovery use the same object, so a concurrent
    replacement of sys.stdout between the failed
    print and discovery cannot redirect a healthy
    stranger's descriptor. A missing stream (None)
    returns at once. ValueError (closed stream) and
    BlockingIOError (transiently full nonblocking
    pipe) are swallowed bare: the descriptor is
    healthy and must survive for later output, so
    discovery is not even consulted — the stream
    retains its buffer for a later flush. On any
    other OSError the failure is contained in two
    ordered phases. Discovery asks the stream for
    its own descriptor OUTSIDE the recovery
    suppression, so a fileno that raises (a
    fileno-less proxy) or returns nothing usable
    cannot skip into a blind fd-1 redirect; only a
    genuine int survives (a str, float, bool, or
    absurd value leaves the stream alone instead of
    raising TypeError/OverflowError out of a
    diagnostic). Recovery repoints the discovered
    descriptor at /dev/null, so interpreter shutdown
    cannot retry the failing flush and turn exit 0
    into exit 120; when the null open itself reuses
    the target fd it is already the recovery —
    closing it would reopen the hole. An
    undiscoverable descriptor, or one aliased to
    stdio (0/2), is left strictly alone: touching fd
    1 there would only destroy healthy output while
    the broken stream is still broken. The shutdown
    outcome then depends on the runtime: bytes
    pending at shutdown fail the final flush (exit
    120), while a failed flush may or may not retain
    its buffer for a retry depending on the version
    (3.12 exits 0 on the bare alias shape, 3.14
    exits 120) — either way unfixable from here and
    documented, not silent (see the proxy
    disposition, deterministic through an
    always-raising write, and the fd2alias
    disposition, which forces the pending state).
    Only the stream's own discovered descriptor is
    ever redirected; the conventional fd is never
    used as a fallback."""
    stream = sys.stdout
    if stream is None:
        return
    try:
        print(message, file=stream, flush=True)
    except ValueError:
        pass
    except BlockingIOError:
        pass
    except OSError:
        try:
            stream_fd = stream.fileno()
        except (OSError, ValueError, AttributeError):
            return
        if type(stream_fd) is not int or stream_fd < 0 \
                or stream_fd in (0, 2):
            return
        with contextlib.suppress(OSError, ValueError,
                                 OverflowError):
            null_fd = os.open("/dev/null", os.O_WRONLY)
            try:
                if null_fd != stream_fd:
                    os.dup2(null_fd, stream_fd)
            finally:
                if null_fd != stream_fd:
                    os.close(null_fd)


def _say_err(message):
    """stderr twin of _say: same dispositions (capture
    the stream once; return at once on None — print
    with file=None would otherwise fall back to
    stdout; swallow ValueError/BlockingIOError bare,
    without consulting discovery; redirect only the
    stream's own discovered int descriptor; leave
    unknown, non-int, or 0/1-aliased descriptors
    alone). Cleanup and last-chance diagnostics must
    never abort their sequence on a broken stderr —
    and must never redirect a descriptor they did
    not discover."""
    stream = sys.stderr
    if stream is None:
        return
    try:
        print(message, file=stream, flush=True)
    except ValueError:
        pass
    except BlockingIOError:
        pass
    except OSError:
        try:
            stream_fd = stream.fileno()
        except (OSError, ValueError, AttributeError):
            return
        if type(stream_fd) is not int or stream_fd < 0 \
                or stream_fd in (0, 1):
            return
        with contextlib.suppress(OSError, ValueError,
                                 OverflowError):
            null_fd = os.open("/dev/null", os.O_WRONLY)
            try:
                if null_fd != stream_fd:
                    os.dup2(null_fd, stream_fd)
            finally:
                if null_fd != stream_fd:
                    os.close(null_fd)


@contextlib.contextmanager
def cancellation():
    """Flag-only cancel scope: the handler notes the signal and
    returns; cancellation takes effect at checkpoints (wait
    slices, explicit flag checks) as explicit InterruptedError.

    A raising handler can never be safe to install here: any
    delivery between a finally's entry and its shield aborts
    the whole cleanup, and any delivery after the last
    checkpoint escapes the evidence repair. With flag-only
    semantics there is no unshielded raising window at all.
    The completion boundary is this scope's single flag read
    below: a flag set before it is repaired (when a repair
    is registered) and raises (exit 1); a flag set after it
    is a post-completion cancel (exit 0 stands).
    """
    def noted(sig, _frame):
        global _CANCEL_REQUESTED
        _CANCEL_REQUESTED = True
    saved = {sig: signal.signal(sig, noted) for sig in (signal.SIGTERM, signal.SIGINT)}
    subreaper()
    try:
        yield
    finally:
        global _CANCELLATION_REPAIR, _CANCELLATION_REAP_FAILED
        # The body's error, captured before the repair can
        # observe anything else: it decides whether the
        # custody failure may replace it below.
        body_error = sys.exception()
        repair, _CANCELLATION_REPAIR = _CANCELLATION_REPAIR, None
        reap_failed = False
        reap_error = None
        try:
            reap_owned()
        except OSError as error:
            # Custody unverifiable (a /proc read failed):
            # tracked independently of cancellation — the
            # repair below still runs (invalidating the
            # published success), and the failure
            # propagates after the handler restore: an
            # unverified reap must fail the lane, never
            # exit 0 past it. Announced on stderr: a
            # parsed stdout must not ingest it.
            reap_failed = True
            reap_error = error
            _say_err(f"sudo-lane: reap failed: {error}")
        _CANCELLATION_REAP_FAILED = reap_failed
        # One read governs both repair and raise: separate
        # checks would race a delivery landing between them
        # (raise without repair). Repair before restoring the
        # foreign handlers: under flag-only semantics nothing
        # can interrupt it, while a restored raising handler
        # could. A repair failure must never break the raise.
        cancelled = _CANCEL_REQUESTED
        if (cancelled or reap_failed) and repair is not None:
            try:
                repair()
            except (OSError, ValueError, MemoryError) as error:
                _say_err(f"sudo-lane: cancel repair failed: {error}")
        for sig, handler in saved.items():
            signal.signal(sig, handler)
        # Total order reap > cancel > body: the custody
        # failure wins over a clean body, lane-control
        # flow (SystemExit — including the sys.exit(0)
        # success path, which must fail closed — and the
        # in-flight cancel raise), and anything the
        # cancel was going to clobber anyway. A genuine
        # body error with no cancel pending propagates
        # untouched: the reap failure is already on
        # stderr and in the repaired evidence, and the
        # one-line diagnostic keeps its root cause.
        if reap_failed and (body_error is None or cancelled
                            or isinstance(body_error, (SystemExit,
                                                      InterruptedError))):
            raise reap_error
        if cancelled:
            raise InterruptedError("cancelled; owned descendants reaped")


def watch_parent_pipe():
    # A pipe survives sudo/unshare without allowing a non-root wrapper to
    # signal arbitrary privileged PIDs. EOF, even after wrapper SIGKILL,
    # cancels the executor. Test bodies never inherit this descriptor.
    def watch():
        # Block the cancel signals on THIS thread too (defense in
        # depth; the thread is already born blocked — see below).
        # pthread_sigmask is per-thread: a signal delivered to an
        # unmasked thread still schedules the Python handler on
        # the main thread — possibly mid-swap inside
        # _deferred_cancel's install, defeating its mask. Every
        # non-main thread must block these; the watcher is the
        # lane's only one.
        signal.pthread_sigmask(signal.SIG_BLOCK,
                               (signal.SIGTERM, signal.SIGINT))
        try:
            while os.read(0, 1):
                pass
        except OSError:
            pass  # lost custody is cancellation, including a hung-up tty
        os.kill(os.getpid(), signal.SIGTERM)
    # Spawn masked: threads inherit the creator's mask, so the
    # watcher is protected from birth. Masking only at watch()
    # entry would leave the spawn-to-entry interval open.
    old_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK, (signal.SIGTERM, signal.SIGINT))
    try:
        threading.Thread(target=watch, daemon=True).start()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def launch_supervised(command):
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, start_new_session=True)
    try:
        # Sliced wait: the flag-only handler cannot break a
        # blocking wait, so poll it. A flag at any slice —
        # including one set as the child exits — raises
        # through the same EOF-and-wait path a raising
        # delivery used to take.
        while True:
            if _CANCEL_REQUESTED:
                raise InterruptedError(
                    "cancelled; requesting privileged cleanup")
            try:
                code = proc.wait(timeout=_WAIT_SLICE)
            except subprocess.TimeoutExpired:
                continue
            if _CANCEL_REQUESTED:
                raise InterruptedError(
                    "cancelled; requesting privileged cleanup")
            return code
    finally:
        # EOF requests cooperative privileged cleanup; the wrapper waits for
        # the executor to release custody instead of abandoning its session.
        proc.stdin.close()
        proc.wait()


def _wait_cancel(proc, *, kill_on_cancel=True):
    """Sliced Popen.wait honoring flag-only cancellation.

    A set flag kills the child, reaps it, and raises; the
    wait itself is unbounded (a D-state child still hangs,
    exactly as under a raising handler). With
    kill_on_cancel=False the child is waited out instead:
    its effect completes and registers, the code is
    returned, and the still-set flag acts at the caller's
    next checkpoint. Mounts use the wait-out shape — a
    kill landing between the mount syscall and the
    registration would leak an unregistered mount.
    """
    while True:
        if _CANCEL_REQUESTED:
            if not kill_on_cancel:
                return proc.wait()
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            proc.wait()
            raise InterruptedError("cancelled during wait")
        try:
            return proc.wait(timeout=_WAIT_SLICE)
        except subprocess.TimeoutExpired:
            continue


def _check_output_cancel(command, *, cwd=None, env=None, text=False):
    """check_output honoring flag-only cancellation.

    Same bytes/exit contract as subprocess.check_output
    (stdout captured, stderr inherited, CalledProcessError
    on nonzero exit); a set flag kills the child and raises
    instead of waiting it out.
    """
    if _CANCEL_REQUESTED:
        raise InterruptedError("cancelled before next command")
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                            cwd=cwd, env=env, text=text)
    while True:
        if _CANCEL_REQUESTED:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            # No drain: a surviving descendant holding the
            # pipe would block EOF forever. The output is
            # discarded on cancel; close our end and reap.
            if proc.stdout is not None:
                with contextlib.suppress(OSError):
                    proc.stdout.close()
            proc.wait()
            raise InterruptedError("cancelled during wait")
        try:
            stdout, _ = proc.communicate(timeout=_WAIT_SLICE)
        except subprocess.TimeoutExpired:
            continue
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(
                proc.returncode, command, output=stdout)
        return stdout


def _run_cancel(command, kill_on_cancel=True, **kwargs):
    """subprocess.run honoring flag-only cancellation (no capture).

    Mounts pass kill_on_cancel=False: the mount runs to
    completion and registers, and cancellation acts at
    the pre-launch check and the next checkpoint instead
    of stranding the effect.
    """
    if _CANCEL_REQUESTED:
        raise InterruptedError("cancelled before next command")
    check = kwargs.pop("check", False)
    proc = subprocess.Popen(command, **kwargs)
    code = _wait_cancel(proc, kill_on_cancel=kill_on_cancel)
    if check and code != 0:
        raise subprocess.CalledProcessError(code, command)
    return subprocess.CompletedProcess(command, code, None, None)


def _copyfile_cancel(source, target, *, dir_fd=None, display=None):
    # Open, never check-then-open: the path may sit
    # under a preparer-writable directory, so a type
    # check races a swap. O_NOFOLLOW refuses symlinks
    # and O_NONBLOCK lets a swapped-in FIFO open to a
    # descriptor that fstat then rejects — either way
    # nothing is followed, read, or hung on. The walk
    # passes its parent descriptor (resolution stays
    # pinned) plus a display path for diagnostics; a
    # direct call resolves from the trusted cwd. The
    # mode comes from the open descriptor too, never
    # from a re-resolved path.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(
                "refusing non-regular stage file: "
                f"{source if display is None else display}")
        with os.fdopen(fd, "rb", closefd=False) as reader, \
                open(target, "wb") as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                if _CANCEL_REQUESTED:
                    raise InterruptedError("cancelled during prepare")
                writer.write(chunk)
            os.fchmod(writer.fileno(),
                      stat.S_IMODE(os.fstat(fd).st_mode))
    finally:
        os.close(fd)


def _copytree_fd_cancel(parent_fd, target, display):
    # Every component resolves relative to its pinned
    # parent directory descriptor: a preparer rename of
    # a walked parent to a symlink mid-copy is
    # traversed as the pinned directory, never
    # re-resolved outside the stage. Per-entry type
    # comes from lstat (no following); the open that
    # consumes the entry re-pins (O_NOFOLLOW for dirs
    # and files, fstat-regular for files), so a swap
    # between the stat and the open still fails
    # closed.
    for name in sorted(os.listdir(parent_fd)):
        if _CANCEL_REQUESTED:
            raise InterruptedError("cancelled during prepare")
        dest = target / name
        shown = f"{display}/{name}"
        mode = os.stat(name, dir_fd=parent_fd,
                       follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode):
            dest.symlink_to(os.readlink(name, dir_fd=parent_fd))
        elif stat.S_ISDIR(mode):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW
                            | os.O_DIRECTORY, dir_fd=parent_fd)
            try:
                dest.mkdir(exist_ok=False)
                _copytree_fd_cancel(child, dest, shown)
            finally:
                os.close(child)
        elif stat.S_ISREG(mode):
            _copyfile_cancel(name, dest, dir_fd=parent_fd,
                             display=shown)
        else:
            raise ValueError(f"refusing exotic stage entry: {shown}")


def _open_pinned(path):
    """Open a directory refusing symlinks at EVERY level.

    O_NOFOLLOW on the final open guards one component
    only: a symlink swapped into an ancestor before the
    open resolves redirects the whole resolution. The
    caller passes an already-resolved absolute path
    (execute's out arrives strict-resolved from main);
    the walk re-opens it component by component from
    the root, each level O_NOFOLLOW|O_NONBLOCK
    relative to its pinned parent plus an fstat
    directory pin, so any symlink — at the top or in
    any ancestor — fails loud (ELOOP) instead of
    redirecting the privileged read. (O_DIRECTORY is
    deliberately NOT combined with O_NOFOLLOW: the
    kernel reports a symlink as ENOTDIR then,
    blurring the refusal; the fstat pin keeps ELOOP
    exact for links and raises ENOTDIR for
    swapped-in non-directories. O_NONBLOCK is what
    keeps a swapped-in FIFO from hanging the open:
    a blocking FIFO open would outwait flag-only
    cancel — PEP 475 retries it — with the lock and
    mount held. An unprivileged preparer cannot
    mknod, so no worse-than-FIFO node is
    placeable; O_PATH would additionally dodge
    root-squash traverse denials, but at the cost
    of hand-mapped errnos.) A swapped-in real
    directory (rename, no symlink) still resolves:
    that residue is gated by content (the stage
    hashes), not by identity. The whole walk runs
    shielded so no signal can strand an
    intermediate descriptor. Ownership transfers
    to the child before the parent closes: a
    parent-close failure releases the owned child
    and never retries the parent number (a failed
    close leaves it possibly released-and-reused).
    Returns the open descriptor; the caller owns
    (closes) it.
    """
    absolute = os.path.abspath(os.fspath(path))
    with _deferred_cancel():
        owned = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in absolute.split("/")[1:]:
                if not component:
                    continue
                # abspath normalizes lexically (. and ..
                # resolved), so every nonempty component
                # is a plain name; each level refuses
                # symlinks, pinning the next resolution
                # to the acquired parent.
                child = os.open(component,
                                os.O_RDONLY | os.O_NOFOLLOW
                                | os.O_NONBLOCK,
                                dir_fd=owned)
                try:
                    if not stat.S_ISDIR(
                            os.fstat(child).st_mode):
                        raise NotADirectoryError(
                            errno.ENOTDIR,
                            "pinned component is not a "
                            f"directory: {component!r}")
                except OSError:
                    try:
                        os.close(child)
                    except OSError:
                        pass
                    raise
                parent, owned = owned, child
                try:
                    os.close(parent)
                except OSError:
                    try:
                        os.close(owned)
                    except OSError:
                        pass
                    owned = None
                    raise
        except OSError:
            if owned is not None:
                try:
                    os.close(owned)
                except OSError:
                    pass
            raise
        return owned


def _copytree_cancel(source, target, *, dir_fd=None, display=None):
    """copytree(symlinks=True) honoring flag-only cancellation.

    Modes need not be preserved (the execute chmod pass
    normalizes everything after). The walk is pinned:
    the top opens O_NOFOLLOW|O_DIRECTORY — relative
    to dir_fd when the caller passes one (execute
    pins out/ so a preparer rename ABOVE the top
    cannot redirect the resolution either) — and
    every component below resolves relative to a
    parent directory descriptor, so a preparer
    rename of a walked directory to a symlink
    mid-copy cannot redirect the resolution outside
    the stage; each consumed file is fstat-pinned
    regular, so a swapped-in symlink or FIFO fails
    closed instead of being followed or hung on.
    """
    target.mkdir(parents=True, exist_ok=False)
    shown = str(source) if display is None else display
    top = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                  dir_fd=dir_fd)
    try:
        _copytree_fd_cancel(top, target, shown)
    finally:
        os.close(top)


def _exclusive_sink(path):
    """Readable fd to a freshly created world-readable regular file.

    O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW: a planted symlink or a
    pre-existing name fails instead of being followed or
    truncated as root. Every call site uses a fresh unique
    name and re-execution into a used directory is refused
    upstream, so refusal always signals tampering or a bug.
    O_RDWR (not O_WRONLY) so the bytes are read back through
    this same descriptor: verdicts and hashes never re-open
    the preparer-writable pathname. The mode is forced (not
    umask-dependent) so failure-uploaded logs stay readable.
    """
    # The shield covers acquisition through the ownership arm: a
    # signal between them would otherwise leak the descriptor
    # (and a leaf path on the create path). Deferral only
    # delays cancellation to the caller's checkpoint.
    with _deferred_cancel():
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o644)
        try:
            os.fchmod(fd, 0o644)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
    return fd


def _read_back(fd):
    """Whole content of a sink after its child is done.

    pread() pins the inode: a renamed-over pathname cannot
    substitute the bytes the verdict and the hash use. The
    child is reaped before this runs, so the size is final;
    a short read can only truncate, and truncated logs fail
    every receipt shape.
    """
    size = os.fstat(fd).st_size
    chunks = []
    offset = 0
    while offset < size:
        chunk = os.pread(fd, size - offset, offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def run_logged(command, log, timeout, cwd=None, env=None, stderr_path=None):
    """No shell expansion; deadlines and cancellation reap the owned tree.

    Returns (exit code, timed out, captured stdout bytes), read back
    through the sink descriptor: callers must verdict on these bytes,
    never re-open the pathname (the directory stays preparer-writable).

    Custody residual (documented, loud): children() and
    reap_owned(proc) in the completion path, plus the
    children() inside the result.json dump dict, are NOT
    contained — a /proc read failure there raises through
    execute (a failed receipt, never green) instead of
    recording locally. Containing them needs a
    leaked-flag design (the runner result is already
    being built when they run); until then the loud
    raise is the contract.
    """
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
    captured = b""
    with contextlib.ExitStack() as stack:
        # Raw descriptors go to the child: no dup/wrap stage means
        # no transfer to fail. Acquisition and ExitStack
        # registration share one shield: a signal between them
        # would otherwise leak the sink with no owner.
        with _deferred_cancel():
            sink = _exclusive_sink(log)
            stack.callback(os.close, sink)
            if stderr_path:
                err_sink = _exclusive_sink(stderr_path)
                stack.callback(os.close, err_sink)
                stderr = err_sink
            else:
                stderr = subprocess.STDOUT
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=sink, stdin=subprocess.DEVNULL,
                                stderr=stderr, start_new_session=True)
        try:
            # Sliced wait against the deadline: the flag-only
            # handler cannot break a blocking wait, so each
            # slice re-checks the flag first. The budget
            # starts at spawn (sink setup is not charged),
            # and terminal status is observed before expiry
            # is declared — an exited child is never
            # mislabeled 124. A flag at any slice —
            # including one set as the child exits — takes
            # the same cancel path a raising delivery used
            # to take.
            deadline = time.monotonic() + timeout
            while True:
                if _CANCEL_REQUESTED:
                    cancelled = True
                    raise InterruptedError("cancelled during wait")
                status = proc.poll()
                if status is not None:
                    code = status
                    if _CANCEL_REQUESTED:
                        cancelled = True
                        raise InterruptedError(
                            "cancelled during wait")
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Re-observe before declaring expiry: the
                    # poll above may be stale (the runner can
                    # be preempted between the two), and an
                    # exited child must never mislabel 124.
                    status = proc.poll()
                    if status is None:
                        timed_out = True
                        code = 124
                        break
                    code = status
                    if _CANCEL_REQUESTED:
                        cancelled = True
                        raise InterruptedError(
                            "cancelled during wait")
                    break
                try:
                    code = proc.wait(
                        timeout=min(_WAIT_SLICE, remaining))
                except subprocess.TimeoutExpired:
                    continue
                if _CANCEL_REQUESTED:
                    cancelled = True
                    raise InterruptedError("cancelled during wait")
                break
        except BaseException:
            cancelled = True
            raise
        finally:
            # Uncontained by design (see the docstring):
            # a custody failure here raises loud through
            # execute — a failed receipt, never green.
            leaked = not timed_out and not cancelled and bool(children())
            reap_owned(proc)
            cancelled = cancelled or _CANCEL_REQUESTED
            # raw_exit is the runner result pre-leak-normalization (124 on
            # timeout, the 1 initializer on cancellation); reaped_status is
            # Popen's wait status once owned children are reaped
            # (negative when the child died on a signal).
            raw_exit = code
            code = normalize_leak(code, leaked)
            captured = _read_back(sink)
            dump(log.with_suffix(log.suffix + ".result.json"), {
                "exit": code, "raw_exit": raw_exit, "reaped_status": proc.returncode,
                "timed_out": timed_out, "cancelled": cancelled,
                "leaked_children": leaked, "pid": proc.pid, "reaped": True,
                # Uncontained like the completion path
                # above (see the docstring).
                "descendants_reaped": not children(),
                "wall_seconds": time.monotonic() - start,
                "log_sha256": hashlib.sha256(captured).hexdigest(),
            })
            if cancelled:
                raise InterruptedError("cancelled; command and descendants reaped")
    return code, timed_out, captured


def source_identity(root):
    paths = _check_output_cancel(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root,
    ).split(b"\0")
    hashes = {}
    for raw in paths:
        if raw:
            path = Path(os.fsdecode(raw))
            if (root / path).is_file():
                hashes[str(path)] = digest(root / path)
    return {
        "head": _check_output_cancel(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
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
        _say(f"sudo-lane: {name}")
        log = logs / f"{name}.log"
        code, _, captured = run_logged(
            command, log, 600, cwd=root, env=env,
            stderr_path=log.with_suffix(".stderr") if name != "bpf-build" else None)
        if code:
            raise ValueError(f"{name} failed ({code}); no privileged execution; see {log}")
        if name != "bpf-build":
            artifacts.extend(cargo_artifacts(captured.decode("utf-8")))
    metadata = json.loads(_check_output_cancel(
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
            code, _, captured = run_logged([row["executable"], "--ignored", "--list", "--format", "terse"], log, 30, cwd=root)
            if code:
                raise ValueError(f"cannot inventory {row['target']}: {log}")
            row["bodies"] = parse_test_list(captured.decode("utf-8"))
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
        if _CANCEL_REQUESTED:
            raise InterruptedError("cancelled during prepare")
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
        if _CANCEL_REQUESTED:
            raise InterruptedError("cancelled during prepare")
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
                  "cargo": _check_output_cancel([cargo, "--version"], cwd=root, env=env, text=True).strip(),
                  "rustc": _check_output_cancel(["rustc", "--version"], cwd=root, env=env, text=True).strip()},
    }
    dump(out / "manifest.json", manifest)
    lab_bodies = len(EXPECTED[LAB_SUITE])
    vng_bodies = len(EXPECTED[VNG_SUITE])
    lane_bodies = sum(len(names) for names in EXPECTED.values()) - lab_bodies - vng_bodies
    # Progress diagnostics fail open: a broken stdout must not
    # turn a prepared lane into a failed one.
    _say(f"sudo-lane: prepared {lane_bodies} lane bodies ({lane_bodies - 1} root, 1 non-root), "
         f"{lab_bodies} separate lab body and {vng_bodies} vng-guest bodies at {out}")
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
    _run_cancel(["mount", "--bind", str(source), str(target)],
                kill_on_cancel=False, check=True)
    mounts.append(target)
    _run_cancel(["mount", "-o", "remount,bind,ro", str(target)],
                kill_on_cancel=False, check=True)


def assert_fresh_execution(out):
    for name in ("ownership.json", "results.json", "summary.json", "runtime.json"):
        if (out / name).exists() or (out / name).is_symlink():
            raise ValueError(f"prepared bundle already attempted execution: {name}; use a fresh bundle")


def execute(out, lock_path, parent_mount_ns, calls, manifest_sha256=None):
    # Drop any repair from an earlier run in this process:
    # the slot repair rewrites unconditionally, so a stale
    # closure must never survive into a new execution (its
    # raise paths return before any registration).
    global _CANCELLATION_REPAIR, _CANCELLATION_REAP_FAILED
    _CANCELLATION_REPAIR = None
    _CANCELLATION_REAP_FAILED = False
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
    # O_RDONLY avoids protected_regular restrictions on user-owned /tmp locks;
    # O_CREAT re-triggers the denial (fs.protected_regular=2 on sticky dirs),
    # so create only when the lock does not exist yet.
    try:
        lane_fd = os.open(lock_path, os.O_RDONLY)
    except FileNotFoundError:
        lane_fd = os.open(lock_path, os.O_RDONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lane_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lane_fd)
        _say_err(f"NOT_RUN sudo-lane: lock held: {lock_path}")
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
    # Failure exits keep a custody invalidator in the slot
    # (the success tail swaps in the cancel backstop): an
    # outer reap failure over a failed execute must still
    # amend the stale claim. Binds the live receipt — the
    # amendment sees its final failed state.
    _CANCELLATION_REPAIR = functools.partial(
        _invalidate_custody_on_reap_failure, out, receipt)
    results, mounts = [], []
    runtime = None
    # This invocation's own failure flag: the end-raise gate must
    # not consult sys.exception(), which also sees exceptions a
    # caller is handling (a caller in `except` would wrongly
    # suppress the publish-failure raise and fall through to a
    # complete summary).
    failed = False
    try:
        # Copy into a root-owned tmpfs whose parent cannot be renamed by
        # the preparer. Verify THAT copy, then mount it read-only. A mutable
        # host staging directory is never an execution source in the lane.
        runtime = Path(tempfile.mkdtemp(prefix="kryprobe-sudo-lane-", dir="/run"))
        runtime.chmod(0o755)
        byte_count = sum((out / relative).stat().st_size for relative in manifest["sha256"])
        if byte_count > 2 * 1024**3:
            raise ValueError("prepared payload exceeds the 2 GiB lane budget")
        _run_cancel(["mount", "-t", "tmpfs", "-o", f"size={byte_count + 256 * 1024**2},mode=0755,nodev",
                        "kryprobe-sudo-lane", str(runtime)],
                    kill_on_cancel=False, check=True)
        mounts.append(runtime)
        # Pin the staging parent before the privileged
        # copy: out/'s ancestors stay preparer-writable,
        # so the top opens relative to this descriptor —
        # and the descriptor itself is acquired by a
        # component walk refusing symlinks at every
        # level (a final-component O_NOFOLLOW alone
        # would sail through a swapped ancestor). The
        # manifest digest above and the stage hashes
        # below still gate the content itself.
        out_fd = _open_pinned(out)
        try:
            _copytree_cancel("stage", runtime / "stage",
                             dir_fd=out_fd,
                             display=str(out / "stage"))
        finally:
            os.close(out_fd)
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
                   KRYPROBE_TEST_TRAFFIC_GENERATOR=str(runtime / "stage/kcrypto_gen.py"),
                   KRYPROBE_BPF_CALLS=str(calls))
        cli = runtime / "stage/debug/kryprobe"
        logs = out / "logs"
        observed = {}
        for index, row in enumerate(manifest["artifacts"]):
            if not row["test"]:
                continue
            log = logs / f"runtime-list-{index}.log"
            code, _, captured = run_logged(
                [str(runtime / row["staged"]), "--ignored", "--list", "--format", "terse"],
                log, 30, cwd=root, env=env)
            bodies = parse_test_list(captured.decode("utf-8")) if code == 0 else []
            if bodies != row["bodies"]:
                raise ValueError(f"runtime body inventory changed: {row['target']}")
            observed[(row["package"], row["target"])] = bodies
        reconcile(observed)
        log = logs / "lifecycle-support.log"
        code, _, captured = run_logged(
            [str(cli), "report", "--system", "--kcrypto-profile", "request-lifecycle",
             "--duration", "1", "--format", "json"], log, 30, cwd=Path("/"), env=env)
        support = lifecycle_verdict(code, captured.decode("utf-8"))
        results.append({"test": "lifecycle-support", "status": support, "log": str(log.relative_to(out))})
        for row in manifest["artifacts"]:
            key = (row["package"], row["target"])
            for body in row["bodies"]:
                result = {"package": key[0], "target": key[1], "test": body,
                          "features": row["features"], "executable_sha256": row["sha256"]}
                if key == LAB_SUITE:
                    result.update(status="OTHER_LANE", reason="requires scenario ledger; run scripts/kcrypto-lab.py")
                elif key == VNG_SUITE:
                    result.update(status="OTHER_LANE",
                                  reason="requires staged vng guest with fixture + BPF object; run the vng-lane guest cells")
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
                    code, timed_out, captured = run_logged(command, log, 180, cwd=root, env=env)
                    output = decode_body_log(captured)
                    status = body_verdict(code, output, key, body)
                    if (key[0], key[1], body) == SELFTEST_BPF_E2E:
                        status, accepted = e2e_partial_guard(output, calls, status)
                        if accepted is not None:
                            result["accepted_partial"] = accepted
                    result.update(status=status,
                                  exit=code, timed_out=timed_out, euid=uid, egid=gid, log=str(log.relative_to(out)))
                results.append(result)
                dump(out / "results.json", results)
                _say(f"sudo-lane: {key[0]}/{key[1]}::{body}: {result['status']}")
        for name, args in [("selftest-bpf", ["selftest", "bpf", "--calls", str(calls)]),
                           ("selftest-token-smoke", ["selftest", "token-smoke"])]:
            log = logs / f"{name}.log"
            code, timed_out, captured = run_logged([str(cli), *args], log, 180, cwd=root, env=env)
            output = decode_body_log(captured)
            status = selftest_verdict(code, output, name, calls)
            result = {"test": name, "status": status, "exit": code,
                      "timed_out": timed_out, "log": str(log.relative_to(out))}
            if status == "PASS" and code == 3 and name == "selftest-bpf":
                accepted = partial_receipt(output, calls)
                if accepted is not None:
                    result["accepted_partial"] = accepted
            results.append(result)
            dump(out / "results.json", results)
        verify_stage(runtime, manifest)
        dump(out / "results.json", results)
        counts = dict(collections.Counter(result["status"] for result in results))
        code = 1 if counts.get("FAIL") else (4 if counts.get("SUPPORTED_REFUSAL") else 0)
        receipt.update(status="finished", exit=code, counts=counts, staged_hashes_unchanged=True)
    except BaseException as error:
        receipt.update(status="failed", exit=1, error=str(error))
        failed = True
        try:
            summary_error = _publish_json(out / "summary.json", {
                "exit": 1, "error": str(error), "complete": False,
                "accepted_partials": summarize_partials(committed_prefix(out, results))})
            if summary_error is not None:
                _say_err(f"sudo-lane: failure summary not published: {summary_error}")
        except (KeyboardInterrupt, SystemExit):
            # Genuine termination (the lane's own cancel arrives
            # as InterruptedError, never this): propagate
            # immediately, like dump's close path. Cleanup still
            # runs — the finally executes regardless.
            raise
        except BaseException as publish_error:
            # A non-OSError escape (allocation class) must not
            # replace the root cause or its termination
            # semantics: chain it and re-raise the original.
            error.__context__ = publish_error
        raise
    finally:
        # Children must be reaped before mounts or the exclusive lock go.
        # The sequence runs shielded: a signal here would otherwise
        # strand mounts, the runtime dir, the ownership receipt, or
        # the lock. Cancellation takes effect through the flag at
        # the end of the sequence.
        with _deferred_cancel():
            # The summaries initialize first: every step
            # below records into them instead of
            # escaping — an OSError anywhere must not
            # strand the unmounts, the receipt, the
            # summary, or the lock.
            publish_errors = []
            deferred = []
            cleanup_errors = []
            try:
                reap_owned()
            except OSError as error:
                cleanup_errors.append({
                    "target": "reap",
                    "stderr": f"reap failed: {error}"})
                reap_failed = True
            else:
                reap_failed = False
            if _CANCEL_REQUESTED:
                receipt.update(status="failed", exit=1, error="cancelled")
                # The site try covers payload evaluation too: the
                # dict build + summarize run before _guarded_publish
                # is entered, and an escape there must defer like
                # any other publish failure.
                try:
                    _guarded_publish(out / "summary.json", {
                        "exit": 1, "complete": False, "error": "cancelled",
                        "accepted_partials": summarize_partials(committed_prefix(out, results))},
                        publish_errors, deferred)
                except BaseException as error:
                    deferred.append(error)
            umount_failed = False
            for target in reversed(mounts):
                # Contained per mount: a spawn failure (fork
                # EAGAIN, missing binary) or an output decode
                # failure must record and continue — never
                # strand the remaining unmounts, the receipt,
                # the summary, and the lock.
                try:
                    cleanup = subprocess.run(
                        ["umount", str(target)],
                        capture_output=True, text=True)
                except (OSError, ValueError) as error:
                    umount_failed = True
                    cleanup_errors.append({
                        "target": str(target),
                        "stderr": f"umount failed: {error}"})
                    continue
                if cleanup.returncode:
                    umount_failed = True
                    cleanup_errors.append({"target": str(target), "stderr": cleanup.stderr})
            # The rmdir gate tracks unmounts only: a reap
            # failure must not skip an otherwise good
            # rmdir (its record lives in cleanup_errors
            # alongside, and the final raise still fires).
            if runtime is not None and not umount_failed:
                # Contained like the unmounts: a busy or
                # foreign runtime dir must record a cleanup
                # error, never skip the receipt, the summary
                # rewrite, and the lock release below.
                try:
                    runtime.rmdir()
                except OSError as error:
                    cleanup_errors.append({
                        "target": str(runtime),
                        "stderr": f"rmdir failed: {error}"})
            try:
                # No re-read after a failed reap: custody
                # was unverified during the unmounts, so a
                # True now would mislead. Runs before the
                # failure summary so a verification failure
                # lands in it like any other cleanup error.
                receipt["children_reaped"] = (
                    not reap_failed and not children())
            except OSError as error:
                receipt["children_reaped"] = False
                cleanup_errors.append({
                    "target": "children",
                    "stderr": f"reap verification failed: {error}"})
            if cleanup_errors:
                receipt.update(status="failed", exit=1, cleanup_errors=cleanup_errors)
                try:
                    _guarded_publish(out / "summary.json", {
                        "exit": 1, "complete": False, "cleanup_errors": cleanup_errors,
                        "accepted_partials": summarize_partials(committed_prefix(out, results))},
                        publish_errors, deferred)
                except BaseException as error:
                    deferred.append(error)
            receipt["owned_mounts_removed"] = not umount_failed
            receipt["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            # A cancel that arrived after the entry check (e.g.
            # during the unmounts) must still reach the receipt.
            # The check sits adjacent to the publish; a flag
            # landing between the two statements is caught by
            # the cancel-raise branch below, which republishes
            # the receipt as cancelled before raising (the
            # post-finally checkpoint never runs on that path,
            # so the correction must happen here).
            if _CANCEL_REQUESTED:
                receipt.update(status="failed", exit=1, error="cancelled")
            try:
                _guarded_publish(out / "ownership.json", receipt, publish_errors, deferred)
            except BaseException as error:
                deferred.append(error)
            if publish_errors or deferred:
                _say_err("sudo-lane: evidence publishing problems: "
                     f"{publish_errors + [type(e).__name__ for e in deferred]}")
            os.close(lane_fd)
            if cleanup_errors:
                error = ValueError(f"owned mount cleanup failed: {cleanup_errors}")
                if deferred:
                    error.__cause__ = deferred[0]
                raise error
            if _CANCEL_REQUESTED:
                # The receipt above may say finished: the flag
                # can land after the adjacent check. Republish
                # as cancelled so the receipt never
                # contradicts the raise (idempotent when the
                # entry check already rewrote it).
                receipt.update(status="failed", exit=1, error="cancelled")
                try:
                    _guarded_publish(out / "ownership.json", receipt,
                                     publish_errors, deferred)
                except BaseException as error:
                    deferred.append(error)
                if publish_errors or deferred:
                    _say_err("sudo-lane: evidence publishing problems: "
                         f"{publish_errors + [type(e).__name__ for e in deferred]}")
                error = InterruptedError("cancelled; lane cleanup complete")
                if deferred:
                    error.__cause__ = deferred[0]
                raise error
            # A new failure here must not mask an in-flight one: the
            # operator already lost the evidence write; keep the root
            # cause (and any termination semantics) intact.
            if not failed:
                if deferred:
                    raise deferred[0]
                if publish_errors:
                    raise ValueError(f"lane evidence publishing failed: {publish_errors}")
    # Final checkpoints: a cancel that landed after the ownership
    # publish — or inside the final dump's own shield — must not
    # leave a complete summary over a cancelled lane. Rewrite the
    # evidence as cancelled through the same guards, then raise;
    # the outer cancellation context observes it too. (Reaching
    # here implies empty problem lists: any finally problem or
    # try failure would already have raised.)
    def publish_cancelled_and_raise():
        receipt.update(status="failed", exit=1, error="cancelled")
        try:
            _guarded_publish(out / "ownership.json", receipt,
                             publish_errors, deferred)
            _guarded_publish(out / "summary.json", {
                "exit": 1, "complete": False, "error": "cancelled",
                "accepted_partials": summarize_partials(
                    committed_prefix(out, results))},
                publish_errors, deferred)
        except BaseException as error:
            deferred.append(error)
        if publish_errors or deferred:
            _say_err("sudo-lane: evidence publishing problems: "
                 f"{publish_errors + [type(e).__name__ for e in deferred]}")
        error = InterruptedError("cancelled; lane cleanup complete")
        if deferred:
            error.__cause__ = deferred[0]
        raise error
    if _CANCEL_REQUESTED:
        publish_cancelled_and_raise()
    # A complete summary is published only after owned processes and
    # mounts are gone. An interrupted cleanup cannot leave a green receipt.
    #
    lab_bodies = len(EXPECTED[LAB_SUITE])
    vng_bodies = len(EXPECTED[VNG_SUITE])
    lane_bodies = sum(len(names) for names in EXPECTED.values()) - lab_bodies - vng_bodies
    try:
        dump(out / "summary.json", {"counts": counts, "exit": code, "expected_bodies": lane_bodies,
                                    "root_bodies": lane_bodies - 1, "nonroot_bodies": 1, "other_lane_bodies": lab_bodies + vng_bodies,
                                    "accepted_partials": summarize_partials(results), "complete": True})
    except BaseException as error:
        # A failed complete dump must not leave a finished
        # receipt over missing evidence: republish as failed
        # (mirroring the L6 cancel branch), then re-raise.
        receipt.update(status="failed", exit=1, error=str(error))
        try:
            _guarded_publish(out / "ownership.json", receipt,
                             publish_errors, deferred)
        except BaseException as nested:
            deferred.append(nested)
        if publish_errors or deferred:
            _say_err("sudo-lane: evidence publishing problems: "
                 f"{publish_errors + [type(e).__name__ for e in deferred]}")
        raise
    if _CANCEL_REQUESTED:
        publish_cancelled_and_raise()
    # Backstop for a flag landing after the post-dump check
    # above: register an evidence repair for the enclosing
    # cancellation scope, consumed exactly once there. The
    # repair is unconditional and memory-only — reaching
    # this line implies a complete summary is on disk (the
    # dump would have raised otherwise, before any
    # registration), so no disk read is needed to decide,
    # and a preparer-swapped summary is overwritten rather
    # than trusted. The accepted partials are snapshotted
    # here, while the disk is known healthy: the repair
    # itself performs zero reads. The post-check repair
    # needs no clearing: it runs before any registration,
    # when the slot cannot be this run's (slot declared
    # global at function entry).
    _CANCELLATION_REPAIR = functools.partial(
        _repair_cancelled_evidence, out, receipt,
        summarize_partials(committed_prefix(out, results)))
    # Contained: a broken stdout must not turn a completed
    # lane into a failed one (complete:true with exit 1).
    _say(f"sudo-lane: {counts}; exit {code}; evidence {out}")
    return code


def _invalidate_custody_on_reap_failure(out, receipt):
    """Amend a failed record's custody claim, on reap failure only.

    Registered in the repair slot right after the running
    receipt publishes (over the LIVE receipt dict, so the
    final failed state is visible) and replaced by the
    cancel backstop at the success tail. A failed execute
    otherwise leaves no slot: an outer custody failure
    would then propagate over a stale children_reaped:true
    with no amendment. No-ops without a reap failure, so a
    merely-cancelled failure keeps its front-line record
    byte-identical (no double-repair). On a reap failure
    it preserves the root-cause text (appending, never
    overwriting) and flips the claim; the summary keeps
    its failed shape (complete:false stands) — the
    custody record of truth is ownership.json plus the
    stderr announcement. Zero reads: values come from the
    bound in-memory receipt.
    """
    if not _CANCELLATION_REAP_FAILED:
        return
    suffix = "owned-descendant reap failed"
    prior = receipt.get("error")
    invalidated = dict(receipt)
    invalidated.update(
        status="failed", exit=1,
        error=f"{prior}; {suffix}" if prior else suffix,
        children_reaped=False)
    repair_errors = []
    repair_deferred = []
    try:
        _guarded_publish(out / "ownership.json", invalidated,
                         repair_errors, repair_deferred)
    except BaseException as error:
        repair_deferred.append(error)
    if repair_errors or repair_deferred:
        _say_err("sudo-lane: evidence publishing problems: "
                 f"{repair_errors + [type(e).__name__ for e in repair_deferred]}")


def _repair_cancelled_evidence(out, receipt, accepted_partials):
    """Rewrite the complete summary as failed, unconditionally.

    Called only with a registered slot, which implies the
    complete dump succeeded. Runs on cancellation AND on an
    outer custody failure without cancel (invalidating the
    published success either way). Decided from control flow,
    not from disk: the out directory stays preparer-writable,
    so reading the summary back would follow symlinks, block on
    FIFOs, and allocate without bound. Values come from the
    bound in-memory receipt and the accepted-partials
    snapshot taken at registration: this function performs
    zero reads (writes only). The error text names the
    trigger (cancel, reap failure, or both); a reap failure
    additionally flips the published children_reaped — a true
    custody claim must not survive an unverified reap.
    """
    if _CANCELLATION_REAP_FAILED and _CANCEL_REQUESTED:
        error_text = "cancelled; owned-descendant reap failed"
    elif _CANCELLATION_REAP_FAILED:
        error_text = "owned-descendant reap failed"
    else:
        error_text = "cancelled"
    repair_receipt = dict(receipt)
    repair_receipt.update(status="failed", exit=1, error=error_text)
    if _CANCELLATION_REAP_FAILED:
        repair_receipt["children_reaped"] = False
    repair_errors = []
    repair_deferred = []
    try:
        _guarded_publish(out / "ownership.json", repair_receipt,
                         repair_errors, repair_deferred)
        _guarded_publish(out / "summary.json", {
            "exit": 1, "complete": False, "error": error_text,
            "accepted_partials": accepted_partials},
            repair_errors, repair_deferred)
    except BaseException as error:
        repair_deferred.append(error)
    if repair_errors or repair_deferred:
        _say_err("sudo-lane: evidence publishing problems: "
             f"{repair_errors + [type(e).__name__ for e in repair_deferred]}")


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
        _say_err(f"FAIL sudo-lane: {error}")
        sys.exit(1)
