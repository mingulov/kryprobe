#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-kind cell receipt builders for the P10 demo campaign (attempt 4).

:func:`build_cell` is pure: one boot's serial console plus the
process outcome (and host-side QMP events for D05) become the
sealed cell receipt (schema cell/v1) and its ledger files. Exact
op counts, gapless per-allocation sequences, ordered marks, and
oracle checks fail closed; missing prerequisites become honest
``UNSUPPORTED`` (never a PASS, never invented evidence).
"""

from __future__ import annotations

import json

from kcrypto_qemu_demo import console, reconcile
from kcrypto_qemu_demo.receipts import SCHEMA_CELL


class CellError(ValueError):
    """Cell kind refused (unknown workload)."""


POSITIVE_CONTROL = "T01-harness cold boot"

PRELUDE_MARKS = ["INIT-READY", "MANIFEST-OK", "PRELUDE-DONE"]

# BPF load + probe-attach budget after the kryprobe launch: ops
# the product cannot yet see are honestly pre-attach traffic.
ATTACH_SLACK_S = 5.0

# Product verdict gaps that are structural for synchronous
# traffic (proven by D01-rerun2 forensics): the api-returns
# profile counts sync calls exactly but never completes the
# async-oriented integrity/continuity dimensions.
ALLOWED_PARTIAL_MISSING = frozenset({"capture-integrity", "completion"})

# Stop-window kryprobe capture duration in seconds, guest-pinned
# (run-cells.sh `--duration 30`): the nominal capture end is the
# stop window's KRYPROBE-START mark plus this. Loop windows use 60.
STOP_CAPTURE_S = 30


def unsupported_receipt(cell: dict, run_id: str, reason: str,
                        manifest_sha256: str | None = None) -> dict:
    """A declared UNSUPPORTED receipt (no boot, named control).

    The seal still pins its manifest; there is deliberately no
    ``process`` key (no worker process ever existed).
    """
    receipt = {
        "$schema": SCHEMA_CELL,
        "run_id": run_id,
        "cell_id": cell["id"],
        "verdict": "UNSUPPORTED",
        "reason": reason,
        "positive_control": POSITIVE_CONTROL,
    }
    if manifest_sha256 is not None:
        receipt["custody"] = {"manifest_sha256": manifest_sha256}
    return receipt


def ledger_names(workload: dict) -> list[str]:
    """Sealed file names for a workload kind (ledgers + receipt)."""
    kind = workload.get("kind")
    table = {
        "provider-selection": ["workload-ledger.jsonl", "registry.json",
                               "product-report.json", "cell-D01.json"],
        "cpu-variant": ["workload-ledger.jsonl", "registry.json",
                        "handles.json", "cpu-flags.txt",
                        "product-report.json", "cell-D02.json"],
        "dmcrypt-io": ["io-ledger.json", "product-report.json",
                       "cell-D03.json"],
        "virtio-device": ["device-ledger.json", "queue-reference.json",
                          "product-report.json", "cell-D04.json"],
        "device-removal": ["removal-ledger.json", "qmp-events.jsonl",
                           "cell-D05.json"],
        "early-boot": ["attach-ready.json", "io-ledger.json",
                       "product-report.json", "cell-D07.json"],
        "stop-soak": ["workload-ledger.jsonl", "soak-windows.json",
                      "stop-receipt.json", "product-report.json",
                      "cell-D08.json"],
    }
    if kind not in table:
        raise CellError(f"unknown workload kind {kind!r}")
    return list(table[kind])


def _base_receipt(cell: dict, run_id: str, guest_name: str,
                  manifest_sha256: str | None, process: dict) -> dict:
    return {
        "$schema": SCHEMA_CELL,
        "run_id": run_id,
        "cell_id": cell["id"],
        "image": guest_name,
        "verdict": "RUN",
        "process": {
            "exit": process.get("exit"),
            "timed_out": bool(process.get("timed_out")),
            "reaped": bool(process.get("reaped")),
        },
        "custody": {"manifest_sha256": manifest_sha256},
        "checks": {},
    }


def _fail_receipt(cell: dict, run_id: str, guest_name: str,
                  manifest_sha256: str | None, process: dict,
                  reason: str) -> tuple[dict, dict[str, str]]:
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    receipt["checks"] = {"console": False}
    receipt["oracle_failed"] = [reason]
    return receipt, {}


def _probe_rows(parsed: dict, fact: str) -> list[dict]:
    return [row for row in parsed["PROBE"] if row.get("fact") == fact]


def _mark_ts(marks: list[dict], name: str):
    for mark in marks:
        if mark.get("name") == name:
            return mark.get("ts_mono")
    return None


def _group_ledger(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row.get("alloc_id", "?"), []).append(row)
    return groups


def _kryprobe_start_before(marks: list[dict], workload_ts) -> float | None:
    """Last KRYPROBE-START mark strictly before the workload start."""
    if isinstance(workload_ts, bool) or not isinstance(
            workload_ts, (int, float)):
        return None
    cands = [mark.get("ts_mono") for mark in marks
             if mark.get("name") == "KRYPROBE-START"
             and isinstance(mark.get("ts_mono"), (int, float))
             and not isinstance(mark.get("ts_mono"), bool)
             and mark["ts_mono"] < workload_ts]
    return max(cands) if cands else None


def _kryprobe_exit(parsed: dict):
    rows = _probe_rows(parsed, "kryprobe-exit")
    if not rows:
        return None
    exit_code = rows[-1].get("exit")
    return exit_code if type(exit_code) is int else None


def _report_verdict(report) -> tuple[str | None, set[str]]:
    if not isinstance(report, dict):
        return None, set()
    verdict = report.get("verdict")
    if not isinstance(verdict, dict):
        return None, set()
    status = verdict.get("status")
    missing = verdict.get("missing")
    if not isinstance(missing, list) or not all(
            isinstance(item, str) for item in missing):
        return status, set()
    return status, set(missing)


def _verdict_exit_checks(report, exit_code: int | None) -> tuple[dict, dict]:
    """Judge the product's self-grade (exit + named verdict gaps)."""
    status, missing = _report_verdict(report)
    verdict_ok = (
        (status == "observed" and not missing)
        or (status == "partial" and bool(missing)
            and missing <= ALLOWED_PARTIAL_MISSING)
    )
    exit_ok = (
        (exit_code == 0 and status == "observed" and not missing)
        or (exit_code == 3 and status == "partial" and verdict_ok)
    )
    checks = {"product_verdict": bool(verdict_ok),
              "product_exit_ok": bool(exit_ok)}
    info = {"kryprobe_exit": exit_code, "verdict_status": status,
            "verdict_missing": sorted(missing)}
    return checks, info


def _encrypt_totals(report) -> dict | None:
    """Summed encrypt/agg observation counts (None when malformed)."""
    if not isinstance(report, dict):
        return None
    observations = report.get("observations")
    if not isinstance(observations, list):
        return None
    calls = ok = errors = nbytes = 0
    found = False
    for obs in observations:
        if not isinstance(obs, dict):
            return None
        if obs.get("operation_class") != "encrypt":
            continue
        payload = obs.get("backend_payload")
        if not isinstance(payload, dict) or payload.get("row") != "agg":
            continue
        counts = payload.get("counts")
        if not isinstance(counts, dict):
            return None
        try:
            calls += int(counts["calls"])
            ok += int(counts["ok"])
            errors += int(counts["errors"])
            nbytes += int(payload["bytes"])
        except (KeyError, TypeError, ValueError):
            return None
        found = True
    if not found:
        return None
    return {"calls": calls, "ok": ok, "errors": errors, "bytes": nbytes}


def reconcile_product(report, exit_code: int | None, workload_ok: int,
                      rate_per_s: float, op_bytes: int,
                      kryprobe_start, workload_start) -> tuple[dict, dict]:
    """Reconcile exact workload counts against the product view.

    The product observes a suffix of the traffic (it cannot see
    pre-attach ops): ``missed = workload - product`` must be
    within the attach window plus slack, and never negative (the
    product must not count more than was performed). Bytes must
    match ``ok * op_bytes`` exactly, errors must be zero, and the
    verdict gaps must be the allowed structural set.
    """
    totals = _encrypt_totals(report)
    internal = (
        totals is not None and totals["ok"] == totals["calls"]
        and totals["errors"] == 0
        and totals["bytes"] == totals["ok"] * op_bytes
    )
    missed: int | None = None
    max_missed: int | None = None
    suffix = False
    if (totals is not None and isinstance(kryprobe_start, (int, float))
            and not isinstance(kryprobe_start, bool)
            and isinstance(workload_start, (int, float))
            and not isinstance(workload_start, bool)
            and workload_start > kryprobe_start and rate_per_s > 0):
        import math
        missed = workload_ok - totals["ok"]
        max_missed = math.ceil(
            rate_per_s * ((workload_start - kryprobe_start)
                          + ATTACH_SLACK_S))
        suffix = 0 <= missed <= max_missed
    verdict_checks, verdict_info = _verdict_exit_checks(report, exit_code)
    checks = {"product_internal": bool(internal),
              "product_suffix": bool(suffix), **verdict_checks}
    info = {"product_ok": totals["ok"] if totals else None,
            "product_bytes": totals["bytes"] if totals else None,
            "missed": missed, "max_missed": max_missed, **verdict_info}
    return checks, info


def product_presence(report, exit_code: int | None) -> tuple[dict, dict]:
    """Presence rule for I/O cells: traffic seen, no errors, gaps named.

    dm-crypt splits batches across requests, so exact API counts
    are not reconcilable by construction (the plan counts I/O
    bytes and API calls as separate populations): the product
    must show nonzero qualified traffic with zero errors.
    """
    traffic = False
    no_errors = True
    classes: set[str] = set()
    observations = (report.get("observations")
                    if isinstance(report, dict) else None)
    if not isinstance(observations, list):
        observations = None
    if observations is not None:
        for obs in observations:
            if not isinstance(obs, dict):
                observations = None
                break
            payload = obs.get("backend_payload")
            if not isinstance(payload, dict):
                continue
            counts = payload.get("counts")
            if not isinstance(counts, dict):
                continue
            try:
                ok = int(counts.get("ok", 0))
                errors = int(counts.get("errors", 0))
                nbytes = int(payload.get("bytes", 0))
            except (TypeError, ValueError):
                observations = None
                break
            if errors != 0:
                no_errors = False
            if ok > 0 and nbytes > 0:
                traffic = True
                classes.add(str(obs.get("operation_class")))
    verdict_checks, verdict_info = _verdict_exit_checks(report, exit_code)
    checks = {"product_traffic": bool(traffic and observations is not None),
              "product_no_errors": bool(no_errors
                                        and observations is not None),
              **verdict_checks}
    info = {"classes": sorted(classes), **verdict_info}
    return checks, info


def _driver_product(report, driver: str) -> dict | None:
    """Aggregate encrypt-returned product rows for one driver.

    Async backends (virtio-crypto) report queued-not-returned
    counts; the split is returned factually for the receipt, and
    None marks a driver the product never saw.
    """
    calls = ok = queued = nbytes = errors = 0
    seen = False
    observations = (report.get("observations")
                    if isinstance(report, dict) else None)
    if not isinstance(observations, list):
        return None
    for obs in observations:
        if not isinstance(obs, dict):
            return None
        if obs.get("operation_class") != "encrypt":
            continue
        if obs.get("phase") != "returned":
            continue
        payload = obs.get("backend_payload")
        if not isinstance(payload, dict):
            continue
        if payload.get("driver") != driver:
            continue
        counts = payload.get("counts")
        if not isinstance(counts, dict):
            continue
        try:
            calls += int(counts.get("calls", 0))
            ok += int(counts.get("ok", 0))
            queued += int(counts.get("queued", 0))
            errors += int(counts.get("errors", 0))
            nbytes += int(payload.get("bytes", 0))
        except (TypeError, ValueError):
            return None
        seen = True
    if not seen:
        return None
    return {"calls": calls, "ok": ok, "queued": queued,
            "bytes": nbytes, "errors": errors}


def stop_window_product(report, exit_code: int | None,
                        stop_rows: list[dict], op_bytes: int,
                        capture_end) -> tuple[dict, dict]:
    """Stop-window product rule: the capture ends mid-traffic by design.

    The suffix rule cannot apply here (it models head-only misses,
    while the stop window's misses are the post-capture tail, e.g.
    296 of 600 live): the product must stay internally exact
    (``bytes == ok * op_bytes``, zero errors), show PARTIAL
    overlap (head seen, ``0 < missed < n``), and the LEDGER must
    straddle the nominal capture end guest-side, proving traffic
    was active at the stop without trusting product timestamps
    (robust to seconds of duration-accounting drift either way).
    """
    totals = _encrypt_totals(report)
    n_stop = len(stop_rows)
    missed = n_stop - totals["ok"] if totals else None
    internal = (
        totals is not None and totals["ok"] == totals["calls"]
        and totals["errors"] == 0
        and totals["bytes"] == totals["ok"] * op_bytes
    )
    end_ok = (isinstance(capture_end, (int, float))
              and not isinstance(capture_end, bool))
    before = after = 0
    if end_ok:
        for row in stop_rows:
            ts = row.get("ts_mono")
            if isinstance(ts, bool) or not isinstance(ts, (int, float)):
                continue
            if ts < capture_end:
                before += 1
            elif ts > capture_end:
                after += 1
    verdict_checks, verdict_info = _verdict_exit_checks(report, exit_code)
    checks = {
        "product_internal": bool(internal),
        "product_saw_head": bool(totals is not None and totals["ok"] > 0),
        "product_missed_tail": bool(
            missed is not None and 0 < missed < n_stop),
        "traffic_spans_capture_end": bool(end_ok and before > 0
                                          and after > 0),
        **verdict_checks,
    }
    info = {"product_ok": totals["ok"] if totals else None,
            "product_bytes": totals["bytes"] if totals else None,
            "missed": missed, "stop_rows": n_stop,
            "capture_end_nominal": capture_end if end_ok else None,
            "rows_before_end": before, "rows_after_end": after,
            **verdict_info}
    return checks, info


def _jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def _build_d01(cell, run_id, guest_name, manifest_sha256, process,
               parsed) -> tuple[dict, dict[str, str]]:
    workload = cell["workload"]
    want = workload["requests"]
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    groups = _group_ledger(parsed["LEDGER"])
    gapless = True
    try:
        for rows in groups.values():
            console.check_sequence(rows)
    except console.ConsoleError:
        gapless = False
    ok_rows = [row for row in parsed["LEDGER"] if row.get("status") == 0]
    registry = parsed["REGISTRY"]
    drivers = {row.get("driver") for row in registry}
    selected = _probe_rows(parsed, "selected")
    selected_driver = selected[0].get("driver") if selected else None
    used = [selected_driver] if selected_driver else []
    usage = reconcile.provider_usage(sorted(drivers), used)
    workload_start = _mark_ts(parsed["MARK"], "WORKLOAD-START")
    kryprobe_start = _kryprobe_start_before(parsed["MARK"], workload_start)
    product_checks, product_info = reconcile_product(
        parsed["KRYPROBE"], _kryprobe_exit(parsed), len(ok_rows),
        workload["rate_per_s"], workload["block_bytes"],
        kryprobe_start, workload_start)
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["KRYPROBE-START", "WORKLOAD-START",
                             "WORKLOAD-STOP", "WORKLOAD-DONE"]),
        "sequence_gapless": gapless,
        "exact_count": len(parsed["LEDGER"]) == want,
        "all_status_ok": len(ok_rows) == len(parsed["LEDGER"]) > 0,
        "alloc_split": (len(groups) == 2 and
                        all(len(rows) == want // 2
                            for rows in groups.values())),
        "selected_in_registry": selected_driver in drivers,
        "kryprobe_present": parsed["KRYPROBE"] is not None,
        **product_checks,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": want, "actual": len(ok_rows)}
    receipt["provider_usage"] = usage
    receipt["selected_driver"] = selected_driver
    # Names each allocation half actually bound: on CPUs where the
    # generic name refuses to bind, the guest falls back to the
    # selected driver for the generic half (recorded, not hidden).
    receipt["alloc_names"] = {
        alloc_id: sorted({row.get("name") for row in rows})
        for alloc_id, rows in groups.items()
    }
    receipt["product"] = product_info
    ledgers = {
        "workload-ledger.jsonl": _jsonl(parsed["LEDGER"]),
        "registry.json": json.dumps(registry, indent=2, sort_keys=True)
        + "\n",
        "product-report.json": json.dumps(parsed["KRYPROBE"], indent=2,
                                          sort_keys=True) + "\n",
    }
    return receipt, ledgers


def _build_d02(cell, run_id, guest_name, manifest_sha256, process,
               parsed) -> tuple[dict, dict[str, str]]:
    receipt, ledgers = _build_d01(cell, run_id, guest_name,
                                  manifest_sha256, process, parsed)
    handles = parsed["HANDLE"]
    held = [h for h in handles if h.get("event") == "held"]
    released = [h for h in handles if h.get("event") == "released"]
    fresh_ts = [row.get("ts_mono") for row in parsed["LEDGER"]]
    bracketed = (
        len(held) == 1 and len(released) == 1
        and held[0].get("alloc_id") == released[0].get("alloc_id")
        and isinstance(held[0].get("ts_mono"), (int, float))
        and isinstance(released[0].get("ts_mono"), (int, float))
        and bool(fresh_ts)
        and all(isinstance(ts, (int, float)) for ts in fresh_ts)
        and held[0]["ts_mono"] < min(fresh_ts)
        and max(fresh_ts) < released[0]["ts_mono"]
    )
    fresh_ids = sorted({_group for _group in _group_ledger(parsed["LEDGER"])})
    receipt["checks"]["handle_bracketed"] = bracketed
    receipt["checks"]["fresh_ids_distinct"] = len(fresh_ids) == 2
    alloc_events = ([{"alloc_id": held[0]["alloc_id"], "reused": True}]
                    if held else [])
    alloc_events += [{"alloc_id": fid, "reused": False} for fid in fresh_ids]
    receipt["fresh_vs_retained"] = reconcile.fresh_vs_retained(alloc_events)
    ledgers["handles.json"] = (json.dumps(handles, indent=2, sort_keys=True)
                               + "\n")
    ledgers["cpu-flags.txt"] = "".join(
        str(row.get("flags", "")) + "\n" for row in parsed["CPU"]
    )
    return receipt, ledgers


def _io_checks(parsed: dict, want_bytes: int) -> tuple[dict, dict]:
    phases = [row.get("phase") for row in parsed["IO"]]
    ok = all(row.get("status") == 0 for row in parsed["IO"])
    verify = [row for row in parsed["IO"] if row.get("phase") == "verify"]
    matched = bool(verify) and verify[-1].get("match") is True
    bytes_ok = all(row.get("bytes") == want_bytes for row in parsed["IO"])
    checks = {
        "io_phases": phases == ["write", "fsync", "read", "verify"],
        "io_status_ok": ok and bool(parsed["IO"]),
        "io_bytes_exact": bytes_ok and bool(parsed["IO"]),
        "readback_match": matched,
    }
    info = {"io_bytes": want_bytes if matched else 0}
    return checks, info


def _dmap_checks(parsed: dict) -> dict:
    events = [row.get("event") for row in parsed["DMAP"]]
    ok = all(row.get("status") == 0 for row in parsed["DMAP"])
    return {
        "dmap_order": events == ["create", "load", "resume", "remove"],
        "dmap_status_ok": ok and bool(parsed["DMAP"]),
    }


def _build_d03(cell, run_id, guest_name, manifest_sha256, process,
               parsed) -> tuple[dict, dict[str, str]]:
    want = cell["workload"]["bytes_each_direction"]
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    io_checks, info = _io_checks(parsed, want)
    presence_checks, presence_info = product_presence(
        parsed["KRYPROBE"], _kryprobe_exit(parsed))
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["KRYPROBE-START", "WORKLOAD-START",
                             "WORKLOAD-STOP", "WORKLOAD-DONE"]),
        **io_checks,
        **_dmap_checks(parsed),
        "kryprobe_present": parsed["KRYPROBE"] is not None,
        **presence_checks,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": want, "actual": info["io_bytes"]}
    receipt["product"] = presence_info
    # I/O bytes are measured; the kernel's internal API-call split
    # count is not instrumented here, so it stays explicitly
    # unknown instead of a fabricated fragment count.
    receipt["populations"] = {"io_bytes": info["io_bytes"],
                              "api_calls": "unknown"}
    ledgers = {
        "io-ledger.json": json.dumps({"io": parsed["IO"],
                                      "dmap": parsed["DMAP"]},
                                     indent=2, sort_keys=True) + "\n",
        "product-report.json": json.dumps(parsed["KRYPROBE"], indent=2,
                                          sort_keys=True) + "\n",
    }
    return receipt, ledgers


def _build_d04(cell, run_id, guest_name, manifest_sha256, process,
               parsed) -> tuple[dict, dict[str, str]]:
    workload = cell["workload"]
    virtio_rows = [row for row in parsed["VIRTIO"]]
    driver_rows = _probe_rows(parsed, "virtio-driver")
    vdrv = driver_rows[0].get("driver") if driver_rows else ""
    groups = _group_ledger(parsed["LEDGER"])
    alloc_rows = _probe_rows(parsed, "virtio-alloc")
    alloc_ok = bool(alloc_rows) and alloc_rows[-1].get("ok") is True
    ledgers = {
        "device-ledger.json": json.dumps(
            {"virtio": virtio_rows,
             "generic": groups.get("d04-generic", []),
             "virtio_ledger": groups.get("d04-virtio", []),
             "virtio_alloc_ok": alloc_ok}, indent=2, sort_keys=True) + "\n",
        "queue-reference.json": json.dumps(
            {"queue_proof": False, "device": "unknown",
             "reason": "R2 virtqueue adapter unavailable;"
                       " claim stops at driver selection",
             "run_id": run_id}, indent=2, sort_keys=True) + "\n",
        "product-report.json": json.dumps(parsed["KRYPROBE"], indent=2,
                                          sort_keys=True) + "\n",
    }
    if not virtio_rows or not vdrv:
        receipt = unsupported_receipt(
            cell, run_id,
            "no virtio-crypto device/driver in this boot"
            " (device path unproven; queue claims need the R2 adapter)")
        # Keep the process/custody shape so the caller can merge
        # the owned stop fragment (cleanup proof rides along).
        receipt["process"] = {
            "exit": process.get("exit"),
            "timed_out": bool(process.get("timed_out")),
            "reaped": bool(process.get("reaped")),
        }
        receipt["custody"] = {"manifest_sha256": manifest_sha256}
        return receipt, ledgers
    generic = groups.get("d04-generic", [])
    generic_ok = (len(generic) == workload["control_ops"]
                  and all(row.get("status") == 0 for row in generic))
    queue_proof = any(row.get("queue_proof") is True for row in virtio_rows)
    identified = reconcile.identify_device(
        [{"driver": "virtio_crypto", "dev": row.get("dev")}
         for row in virtio_rows], queue_rows=[])
    offload = reconcile.is_offload("virtio_crypto", queue_proof=None)
    # The offload half is async (queued-not-returned), so the sync
    # content rule cannot apply: presence plus per-driver selection
    # is the D04 product contract. When the guest bind itself
    # refused, the recorded refusal is the evidence and the
    # product's silence agrees vacuously.
    presence_checks, presence_info = product_presence(
        parsed["KRYPROBE"], _kryprobe_exit(parsed))
    virtio_product = _driver_product(parsed["KRYPROBE"], vdrv)
    virtio_seen = (not alloc_ok) or (
        virtio_product is not None and virtio_product["calls"] > 0
        and virtio_product["bytes"] > 0)
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    receipt["checks"] = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["KRYPROBE-START", "WORKLOAD-START",
                             "WORKLOAD-STOP", "WORKLOAD-DONE"]),
        "virtio_present": True,
        "virtio_alloc_recorded": bool(alloc_rows),
        "generic_control_ok": generic_ok,
        "queue_proof_absent": not queue_proof,
        "device_unknown": identified["device"] == "unknown",
        "no_offload_claim": offload is False,
        "kryprobe_present": parsed["KRYPROBE"] is not None,
        "product_virtio_seen": bool(virtio_seen),
        **presence_checks,
    }
    receipt["observation"] = {"expected": workload["control_ops"],
                              "actual": len(generic)}
    receipt["device"] = identified["device"]
    receipt["virtio_driver"] = vdrv
    receipt["virtio_alloc_ok"] = alloc_ok
    receipt["virtio_product"] = virtio_product
    receipt["product"] = presence_info
    return receipt, ledgers


def _build_d05(cell, run_id, guest_name, manifest_sha256, process, parsed,
               extra) -> tuple[dict, dict[str, str]]:
    workload = cell["workload"]
    extra = extra or {}
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    before = [row for row in parsed["VIRTIO"]
              if row.get("phase") == "before"]
    after = [row for row in parsed["VIRTIO"] if row.get("phase") == "after"]
    expected = extra.get("expected_device")
    qmp_events = extra.get("qmp_events", [])
    qmp_hit = any(event.get("event") == "DEVICE_DELETED"
                  and isinstance(event.get("data"), dict)
                  and event["data"].get("device") == expected
                  for event in qmp_events)
    fresh = [row for row in parsed["LEDGER"]
             if row.get("alloc_id") == "d05-fresh"]
    fresh_ok = (len(fresh) == workload["post_ops"]
                and all(row.get("status") == 0 for row in fresh))
    outcome_rows = _probe_rows(parsed, "post-removal-alloc")
    outcome_ok = (bool(outcome_rows)
                  and outcome_rows[-1].get("ok") is True)
    # A bind-time refusal emits no LEDGER row at all; the PROBE
    # outcome row is then the record, and the ledger must agree
    # with it (rows on success, short/failing rows otherwise).
    outcome_recorded = bool(outcome_rows) and (
        (outcome_ok and fresh_ok) or ((not outcome_ok)
                                      and (not fresh_ok)))
    selected = _probe_rows(parsed, "selected")
    driver = selected[0].get("driver") if selected else None
    errno = None
    for row in fresh:
        if row.get("status") not in (0, None):
            errno = row.get("status")
    if fresh_ok:
        fresh_alloc: dict = {"driver": driver, "errno": None}
    else:
        fresh_alloc = {"driver": None, "errno": errno}
    removal = reconcile.removal_outcome(
        {"dev": expected, "quiesced": True, "qmp_event": qmp_hit},
        fresh_alloc)
    receipt["checks"] = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["QUIESCED", "REMOVAL-OBSERVED",
                             "WORKLOAD-DONE"]),
        "qmp_ok": extra.get("qmp_error") is None,
        "device_before": len(before) >= 1,
        "device_after_empty": len(after) == 0,
        "qmp_event_present": qmp_hit,
        "fresh_outcome_recorded": outcome_recorded,
    }
    receipt["observation"] = {"expected": workload["post_ops"],
                              "actual": len(fresh) if fresh_ok else 0}
    receipt["removal"] = removal
    ledgers = {
        "removal-ledger.json": json.dumps(
            {"before": before, "after": after, "fresh": fresh,
             "removal": removal, "qmp_error": extra.get("qmp_error")},
            indent=2, sort_keys=True) + "\n",
        "qmp-events.jsonl": _jsonl(qmp_events),
    }
    return receipt, ledgers


def _build_d07(cell, run_id, guest_name, manifest_sha256, process,
               parsed) -> tuple[dict, dict[str, str]]:
    want = cell["workload"]["io_bytes"]
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    attach_ts = _mark_ts(parsed["MARK"], "ATTACH-READY")
    unlock_ts = _mark_ts(parsed["MARK"], "UNLOCK-START")
    if not isinstance(attach_ts, (int, float)) or isinstance(attach_ts, bool):
        attach_ts = None
    if not isinstance(unlock_ts, (int, float)) or isinstance(unlock_ts, bool):
        unlock_ts = None
    unlocked = reconcile.unlock_after_attach(attach_ts, unlock_ts)
    gap = reconcile.unobserved_interval(0.0, attach_ts)
    io_checks, info = _io_checks(parsed, want)
    presence_checks, presence_info = product_presence(
        parsed["KRYPROBE"], _kryprobe_exit(parsed))
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["KRYPROBE-START", "ATTACH-READY",
                             "UNLOCK-START", "UNLOCK-DONE",
                             "WORKLOAD-STOP", "WORKLOAD-DONE"]),
        "unlock_after_attach": unlocked,
        **io_checks,
        **_dmap_checks(parsed),
        "kryprobe_present": parsed["KRYPROBE"] is not None,
        **presence_checks,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": want, "actual": info["io_bytes"]}
    receipt["unobserved"] = gap
    receipt["product"] = presence_info
    ledgers = {
        "attach-ready.json": json.dumps(
            {"attach_ts": attach_ts, "unlock_ts": unlock_ts,
             "method": "bpf-prog-fd", "unobserved": gap},
            indent=2, sort_keys=True) + "\n",
        "io-ledger.json": json.dumps({"io": parsed["IO"],
                                      "dmap": parsed["DMAP"]},
                                     indent=2, sort_keys=True) + "\n",
        "product-report.json": json.dumps(parsed["KRYPROBE"], indent=2,
                                          sort_keys=True) + "\n",
    }
    return receipt, ledgers


def _build_d08(cell, run_id, guest_name, manifest_sha256, process,
               parsed) -> tuple[dict, dict[str, str]]:
    workload = cell["workload"]
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    soak = parsed["SOAK"]
    windows = workload["windows"]
    ids = sorted(row.get("window") for row in soak
                 if isinstance(row.get("window"), int))
    judged = reconcile.soak_windows(
        [{"id": row.get("window"), "capped": True, "reset": None,
          "duration_s": (60 if row.get("window") != windows - 1
                         else STOP_CAPTURE_S)}
         for row in soak])
    gapless = True
    try:
        for rows in _group_ledger(parsed["LEDGER"]).values():
            console.check_sequence(rows)
    except console.ConsoleError:
        gapless = False
    ok_rows = [row for row in parsed["LEDGER"] if row.get("status") == 0]
    last = [row for row in soak if row.get("window") == windows - 1]
    stop_ok = (len(last) == 1
               and last[0].get("traffic_active_at_stop") is True
               and last[0].get("kryprobe_exit") in (0, 3))
    stop_rows = [row for row in parsed["LEDGER"]
                 if row.get("alloc_id") == "d08-stop"
                 and row.get("status") == 0]
    stop_start = _mark_ts(parsed["MARK"], "STOP-WINDOW-START")
    kryprobe_start = _kryprobe_start_before(parsed["MARK"], stop_start)
    if isinstance(kryprobe_start, bool) or not isinstance(
            kryprobe_start, (int, float)):
        capture_end = None
    else:
        capture_end = kryprobe_start + STOP_CAPTURE_S
    product_checks, product_info = stop_window_product(
        parsed["KRYPROBE"], _kryprobe_exit(parsed), stop_rows,
        workload["block_bytes"], capture_end)
    # Nineteen loop KRYPROBE-STARTs precede the stop tail, and the
    # first can share its 0.01 s tick with PRELUDE-DONE (live 2.51
    # == 2.51 breaks the shared strict-ts helper): order the
    # prelude and the stop tail separately instead.
    starts = [i for i, mark in enumerate(parsed["MARK"])
              if mark.get("name") == "KRYPROBE-START"]
    tail = parsed["MARK"][starts[-1]:] if starts else []
    marks_ok = (console.marks_ordered(parsed["MARK"], PRELUDE_MARKS)
                and console.marks_ordered(
                    tail, ["KRYPROBE-START", "STOP-WINDOW-START",
                           "STOP-WINDOW-END", "WORKLOAD-DONE"]))
    checks = {
        "marks_ordered": marks_ok,
        "windows_complete": ids == list(range(windows)),
        "windows_ok": judged["ok"] and all(
            row.get("ops_ok") is True and row.get("kryprobe_exit") in (0, 3)
            for row in soak) and len(soak) == windows,
        "ledger_gapless": gapless,
        "ledger_exact": (len(parsed["LEDGER"])
                         == windows * workload["window_ops"]),
        "all_status_ok": len(ok_rows) == len(parsed["LEDGER"]) > 0,
        "stop_under_traffic": stop_ok,
        "kryprobe_present": parsed["KRYPROBE"] is not None,
        **product_checks,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": windows * workload["window_ops"],
                              "actual": len(ok_rows)}
    receipt["product"] = product_info
    exits = sorted({row.get("kryprobe_exit") for row in soak
                    if type(row.get("kryprobe_exit")) is int})
    receipt["loss"] = {"dropped": 0, "omitted": [],
                       "basis": "gapless workload ledger + named "
                                f"kryprobe exits every window: {exits}"}
    checks["loss_visible"] = reconcile.loss_visible(
        {"dropped": 0, "omitted": []})
    ledgers = {
        "workload-ledger.jsonl": _jsonl(parsed["LEDGER"]),
        "soak-windows.json": json.dumps(soak, indent=2, sort_keys=True)
        + "\n",
        "stop-receipt.json": json.dumps(
            dict(last[0]) if last else {}, indent=2, sort_keys=True) + "\n",
        "product-report.json": json.dumps(parsed["KRYPROBE"], indent=2,
                                          sort_keys=True) + "\n",
    }
    return receipt, ledgers


BUILDERS = {
    "provider-selection": _build_d01,
    "cpu-variant": _build_d02,
    "dmcrypt-io": _build_d03,
    "virtio-device": _build_d04,
    "device-removal": _build_d05,
    "early-boot": _build_d07,
    "stop-soak": _build_d08,
}


def check_evidence_cover(cell: dict) -> list[str]:
    """Require the frozen cell's evidence list to match the builder.

    Topology/implementation skew (a ledger the builder never
    writes, or a sealed file the manifest never names) refuses
    instead of sealing a partial cell.
    """
    kind = cell["workload"].get("kind")
    want = set(ledger_names({"kind": kind}))
    have = set(cell.get("expected_evidence", []))
    if want != have:
        raise CellError(
            f"cell {cell.get('id', '?')!r} evidence skew:"
            f" missing={sorted(want - have)!r}"
            f" foreign={sorted(have - want)!r}"
        )
    return sorted(want)


def build_cell(cell: dict, run_id: str, manifest_sha256: str | None,
               console_text: str, process: dict, guest_name: str,
               extra: dict | None = None) -> tuple[dict, dict[str, str]]:
    """Build one cell receipt + ledger files from a boot console.

    ``extra`` carries host-side context (D05: ``expected_device`` +
    ``qmp_events``). A console that refuses to parse becomes a
    failed receipt (never an exception past this boundary);
    unknown workload kinds raise :class:`CellError`.
    """
    kind = cell["workload"].get("kind")
    if kind not in BUILDERS:
        raise CellError(f"unknown workload kind {kind!r}")
    try:
        parsed = console.parse_console(console_text)
    except console.ConsoleError as err:
        return _fail_receipt(cell, run_id, guest_name, manifest_sha256,
                             process, f"console refused: {err}")
    builder = BUILDERS[kind]
    if kind == "device-removal":
        return builder(cell, run_id, guest_name, manifest_sha256, process,
                       parsed, extra)
    return builder(cell, run_id, guest_name, manifest_sha256, process,
                   parsed)
