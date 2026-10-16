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
import fcntl
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
                print("FAIL sudo-lane: cleanup pending; retaining lane until owned children are reaped", file=sys.stderr, flush=True)
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

    OSError/ValueError (broken pipe, closed stream) are
    swallowed so cleanup reports never abort the sequence;
    MemoryError stays uncatchable-narrow (see _guarded_publish
    for the deferred escape)."""
    try:
        print(message, flush=True)
    except (OSError, ValueError):
        pass


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
        return proc.wait()
    finally:
        # EOF requests cooperative privileged cleanup; the wrapper waits for
        # the executor to release custody instead of abandoning its session.
        proc.stdin.close()
        proc.wait()


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
                "descendants_reaped": not children(),
                "wall_seconds": time.monotonic() - start,
                "log_sha256": hashlib.sha256(captured).hexdigest(),
            })
            if cancelled:
                raise InterruptedError("cancelled; command and descendants reaped")
    return code, timed_out, captured


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
        code, _, captured = run_logged(
            command, log, 600, cwd=root, env=env,
            stderr_path=log.with_suffix(".stderr") if name != "bpf-build" else None)
        if code:
            raise ValueError(f"{name} failed ({code}); no privileged execution; see {log}")
        if name != "bpf-build":
            artifacts.extend(cargo_artifacts(captured.decode("utf-8")))
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
    lab_bodies = len(EXPECTED[LAB_SUITE])
    vng_bodies = len(EXPECTED[VNG_SUITE])
    lane_bodies = sum(len(names) for names in EXPECTED.values()) - lab_bodies - vng_bodies
    print(f"sudo-lane: prepared {lane_bodies} lane bodies ({lane_bodies - 1} root, 1 non-root), "
          f"{lab_bodies} separate lab body and {vng_bodies} vng-guest bodies at {out}", flush=True)
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
                print(f"sudo-lane: {key[0]}/{key[1]}::{body}: {result['status']}", flush=True)
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
                _say(f"sudo-lane: failure summary not published: {summary_error}")
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
            reap_owned()
            publish_errors = []
            deferred = []
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
            cleanup_errors = []
            for target in reversed(mounts):
                cleanup = subprocess.run(["umount", str(target)], capture_output=True, text=True)
                if cleanup.returncode:
                    cleanup_errors.append({"target": str(target), "stderr": cleanup.stderr})
            if runtime is not None and not cleanup_errors:
                runtime.rmdir()
            if cleanup_errors:
                receipt.update(status="failed", exit=1, cleanup_errors=cleanup_errors)
                try:
                    _guarded_publish(out / "summary.json", {
                        "exit": 1, "complete": False, "cleanup_errors": cleanup_errors,
                        "accepted_partials": summarize_partials(committed_prefix(out, results))},
                        publish_errors, deferred)
                except BaseException as error:
                    deferred.append(error)
            receipt["children_reaped"] = not children()
            receipt["owned_mounts_removed"] = not cleanup_errors
            receipt["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            # A cancel that arrived after the entry check (e.g.
            # during the unmounts) must still reach the receipt.
            # The check sits adjacent to the publish; the
            # residual check-act race (a deferred signal landing
            # between the two statements) still cancels the exit
            # at the end — only the receipt status could lag by
            # one publish, and the final checkpoint below
            # corrects even that.
            if _CANCEL_REQUESTED:
                receipt.update(status="failed", exit=1, error="cancelled")
            try:
                _guarded_publish(out / "ownership.json", receipt, publish_errors, deferred)
            except BaseException as error:
                deferred.append(error)
            if publish_errors or deferred:
                _say("sudo-lane: evidence publishing problems: "
                     f"{publish_errors + [type(e).__name__ for e in deferred]}")
            os.close(lane_fd)
            if cleanup_errors:
                error = ValueError(f"owned mount cleanup failed: {cleanup_errors}")
                if deferred:
                    error.__cause__ = deferred[0]
                raise error
            if _CANCEL_REQUESTED:
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
            _say("sudo-lane: evidence publishing problems: "
                 f"{publish_errors + [type(e).__name__ for e in deferred]}")
        error = InterruptedError("cancelled; lane cleanup complete")
        if deferred:
            error.__cause__ = deferred[0]
        raise error
    if _CANCEL_REQUESTED:
        publish_cancelled_and_raise()
    # A complete summary is published only after owned processes and
    # mounts are gone. An interrupted cleanup cannot leave a green receipt.
    lab_bodies = len(EXPECTED[LAB_SUITE])
    vng_bodies = len(EXPECTED[VNG_SUITE])
    lane_bodies = sum(len(names) for names in EXPECTED.values()) - lab_bodies - vng_bodies
    dump(out / "summary.json", {"counts": counts, "exit": code, "expected_bodies": lane_bodies,
                                "root_bodies": lane_bodies - 1, "nonroot_bodies": 1, "other_lane_bodies": lab_bodies + vng_bodies,
                                "accepted_partials": summarize_partials(results), "complete": True})
    if _CANCEL_REQUESTED:
        publish_cancelled_and_raise()
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
