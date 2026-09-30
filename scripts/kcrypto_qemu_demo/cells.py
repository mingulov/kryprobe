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


def unsupported_receipt(cell: dict, run_id: str, reason: str) -> dict:
    """A declared UNSUPPORTED receipt (no boot, named control)."""
    return {
        "$schema": SCHEMA_CELL,
        "run_id": run_id,
        "cell_id": cell["id"],
        "verdict": "UNSUPPORTED",
        "reason": reason,
        "positive_control": POSITIVE_CONTROL,
    }


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
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["WORKLOAD-START", "WORKLOAD-STOP",
                             "WORKLOAD-DONE"]),
        "sequence_gapless": gapless,
        "exact_count": len(parsed["LEDGER"]) == want,
        "all_status_ok": len(ok_rows) == len(parsed["LEDGER"]) > 0,
        "alloc_split": (len(groups) == 2 and
                        all(len(rows) == want // 2
                            for rows in groups.values())),
        "selected_in_registry": selected_driver in drivers,
        "kryprobe_present": parsed["KRYPROBE"] is not None,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": want, "actual": len(ok_rows)}
    receipt["provider_usage"] = usage
    receipt["selected_driver"] = selected_driver
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
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["WORKLOAD-START", "WORKLOAD-STOP",
                             "WORKLOAD-DONE"]),
        **io_checks,
        **_dmap_checks(parsed),
        "kryprobe_present": parsed["KRYPROBE"] is not None,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": want, "actual": info["io_bytes"]}
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
        return receipt, ledgers
    generic = groups.get("d04-generic", [])
    generic_ok = (len(generic) == workload["control_ops"]
                  and all(row.get("status") == 0 for row in generic))
    queue_proof = any(row.get("queue_proof") is True for row in virtio_rows)
    identified = reconcile.identify_device(
        [{"driver": "virtio_crypto", "dev": row.get("dev")}
         for row in virtio_rows], queue_rows=[])
    offload = reconcile.is_offload("virtio_crypto", queue_proof=None)
    receipt = _base_receipt(cell, run_id, guest_name, manifest_sha256,
                            process)
    receipt["checks"] = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["WORKLOAD-START", "WORKLOAD-STOP",
                             "WORKLOAD-DONE"]),
        "virtio_present": True,
        "virtio_alloc_recorded": bool(alloc_rows),
        "generic_control_ok": generic_ok,
        "queue_proof_absent": not queue_proof,
        "device_unknown": identified["device"] == "unknown",
        "no_offload_claim": offload is False,
        "kryprobe_present": parsed["KRYPROBE"] is not None,
    }
    receipt["observation"] = {"expected": workload["control_ops"],
                              "actual": len(generic)}
    receipt["device"] = identified["device"]
    receipt["virtio_driver"] = vdrv
    receipt["virtio_alloc_ok"] = alloc_ok
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
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["ATTACH-READY", "UNLOCK-START",
                             "UNLOCK-DONE", "WORKLOAD-STOP",
                             "WORKLOAD-DONE"]),
        "unlock_after_attach": unlocked,
        **io_checks,
        **_dmap_checks(parsed),
        "kryprobe_present": parsed["KRYPROBE"] is not None,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": want, "actual": info["io_bytes"]}
    receipt["unobserved"] = gap
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
          "duration_s": 60 if row.get("window") != windows - 1 else 30}
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
               and last[0].get("kryprobe_exit") == 0)
    checks = {
        "marks_ordered": console.marks_ordered(
            parsed["MARK"],
            PRELUDE_MARKS + ["STOP-WINDOW-START", "STOP-WINDOW-END",
                             "WORKLOAD-DONE"]),
        "windows_complete": ids == list(range(windows)),
        "windows_ok": judged["ok"] and all(
            row.get("ops_ok") is True and row.get("kryprobe_exit") == 0
            for row in soak) and len(soak) == windows,
        "ledger_gapless": gapless,
        "ledger_exact": (len(parsed["LEDGER"])
                         == windows * workload["window_ops"]),
        "all_status_ok": len(ok_rows) == len(parsed["LEDGER"]) > 0,
        "stop_under_traffic": stop_ok,
        "kryprobe_present": parsed["KRYPROBE"] is not None,
    }
    receipt["checks"] = checks
    receipt["observation"] = {"expected": windows * workload["window_ops"],
                              "actual": len(ok_rows)}
    receipt["loss"] = {"dropped": 0, "omitted": [],
                         "basis": "gapless workload ledger + kryprobe"
                                  " exit 0 (clean/complete) every window"}
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
