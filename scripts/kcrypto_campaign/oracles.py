#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""P8/T13 real-consumer oracles: pure checker predicates over archived facts.

Every ``check_*`` function is pure (dicts in, ``(checks,
detail)`` out); the campaign CLI's ``verify`` step loads each
sealed cell directory and calls these. ``reconcile.verify``
gates on the returned ``checks`` (every value must be exactly
``True``).

Counting rules (never violated):

- Product counts are compared to an INDEPENDENT reference (the
  fixture ledger, an ftrace kernel count, a workload ledger) —
  never to the product's own totals, and never by equating
  bytes/packets to API calls without the proved relation.
- Byte/call relations are proved per cell: exact byte
  reconciliation PLUS exact call equality against the kernel
  reference PLUS the explained chunking shape.
- The report parser understands only the pinned ``report
  --system --format json`` shape (``observations``/``coverage``/
  ``integrity``/``verdict``); unknown rows fail, exact-duplicate
  observations collapse (counted), conflicting same-key rows
  fail.
"""

from __future__ import annotations

# Exit code of LiveError::Unusable (live.rs): the typed refusal
# for gate/detect/object/denied bring-up. Exit 1 is an internal
# defect, never a refusal.
EXIT_UNUSABLE = 4

REQUIRED_REPORT_KEYS = frozenset({"observations", "coverage", "integrity", "verdict"})

REQUIRED_WHO_KEYS = frozenset({"tgid", "calls"})


class OracleError(ValueError):
    """Oracle input refusal: the archived facts are not the pinned shape."""


def parse_api_returns_report(doc: dict) -> dict:
    """Parse a pinned ``report --system --format json`` document.

    Returns ``{"agg": {(family, op, result): {"calls", "errors",
    "ok", "queued", "bytes", "drivers", "algorithms"}}, "who":
    [{tgid, tid, comm, uid, calls, first_errno}], "totals":
    {...}, "loss": {"ring_drops", "ktot_gap", ...integrity
    counters}, "verdict": {...}, "duplicates_collapsed": n}``.
    Raises :class:`OracleError` on missing keys, unknown rows,
    conflicting same-key agg rows, or who rows without identity.
    """
    if not isinstance(doc, dict):
        raise OracleError(f"report top level must be an object, got {type(doc).__name__}")
    missing = REQUIRED_REPORT_KEYS - doc.keys()
    if missing:
        raise OracleError(f"report missing keys: {sorted(missing)}")
    observations = doc["observations"]
    if not isinstance(observations, list):
        raise OracleError("report 'observations' must be a list")
    agg: dict[tuple, dict] = {}
    who: list[dict] = []
    totals: dict = {}
    duplicates = 0
    seen_payloads: set[str] = set()
    import json as _json

    for obs in observations:
        if not isinstance(obs, dict):
            raise OracleError(f"observation must be an object, got {obs!r}")
        payload = obs.get("backend_payload")
        if not isinstance(payload, dict):
            raise OracleError(f"observation {obs.get('id', '?')!r} has no backend_payload")
        row = payload.get("row")
        if row == "agg":
            key = (payload.get("family"), payload.get("op"), payload.get("result"))
            counts = payload.get("counts")
            if not isinstance(counts, dict):
                raise OracleError(f"agg row {key!r} has no counts mapping")
            fingerprint = _json.dumps(payload, sort_keys=True)
            if fingerprint in seen_payloads:
                duplicates += 1
                continue
            seen_payloads.add(fingerprint)
            if key in agg:
                raise OracleError(f"conflicting agg rows for {key!r}")
            agg[key] = {
                "calls": counts.get("calls"),
                "errors": counts.get("errors"),
                "ok": counts.get("ok"),
                "queued": counts.get("queued"),
                "bytes": payload.get("bytes"),
                "drivers": payload.get("driver"),
                "algorithms": payload.get("algorithm"),
            }
        elif row == "who":
            missing_who = REQUIRED_WHO_KEYS - payload.keys()
            if missing_who:
                raise OracleError(
                    f"who row missing identity keys: {sorted(missing_who)}"
                )
            who.append(
                {
                    "tgid": payload["tgid"],
                    "tid": payload.get("tid"),
                    "comm": payload.get("comm"),
                    "uid": payload.get("uid"),
                    "calls": payload["calls"],
                    "first_errno": payload.get("first_errno"),
                }
            )
        elif row == "totals":
            totals = {
                "counts": payload.get("counts"),
                "bytes": payload.get("bytes"),
                "window": payload.get("window"),
            }
        elif row == "ident":
            # Transform-identity rows carry no call counts; they
            # must not be mistaken for traffic evidence.
            continue
        else:
            raise OracleError(f"unknown row {row!r} in observation {obs.get('id', '?')!r}")
    loss: dict[str, str] = {}
    coverage = doc["coverage"]
    if not isinstance(coverage, dict):
        raise OracleError("report 'coverage' must be an object")
    for dim in ("aggregate_counts", "detailed_events"):
        counters = coverage.get(dim, {}).get("counters", [])
        for counter in counters:
            if isinstance(counter, dict) and "name" in counter:
                loss[counter["name"]] = counter.get("value")
    integrity = doc["integrity"]
    if not isinstance(integrity, dict):
        raise OracleError("report 'integrity' must be an object")
    for name in (
        "ring_reservation_failures",
        "user_queue_drops",
        "state_insert_failures",
        "budget_omissions",
    ):
        if name in integrity:
            loss[name] = integrity[name]
    return {
        "agg": agg,
        "who": who,
        "totals": totals,
        "loss": loss,
        "verdict": doc["verdict"],
        "duplicates_collapsed": duplicates,
    }


def _zero_loss(loss: dict, *names: str) -> bool:
    return all(loss.get(name) == "0" for name in names)


def check_r01_det(leg_a: dict, leg_b: dict) -> tuple[dict, dict]:
    """R01 deterministic fixture legs: identical semantic counts twice.

    Each leg carries ``ledger_ops`` (fixture truth), ``ledger_rc``
    (strict testkit validation exit), ``attach_markers`` (proven
    observer attach count) and ``product`` (observed per-family
    counts). Determinism = exact equality of every semantic
    count across both legs with both ledgers valid.
    """
    checks = {}
    checks["ledgers_valid"] = leg_a.get("ledger_rc") == 0 and leg_b.get("ledger_rc") == 0
    checks["attach_proved"] = bool(leg_a.get("attach_markers")) and bool(
        leg_b.get("attach_markers")
    )
    checks["ledger_deterministic"] = leg_a.get("ledger_ops") == leg_b.get("ledger_ops")
    checks["deterministic_counts"] = leg_a.get("product") == leg_b.get("product")
    detail = {
        "ledger_ops": leg_a.get("ledger_ops"),
        "product": leg_a.get("product"),
    }
    return checks, detail


def check_r01_floor(aggregate: dict, refusal: dict) -> tuple[dict, dict]:
    """R01 6.12 floor: supported aggregate exact + lifecycle refusal typed.

    ``aggregate`` carries ``hash_issued``/``hash_observed``,
    ``skc_issued``/``skc_enc_observed``/``skc_dec_observed`` and
    ``ring_drops``; ``refusal`` carries ``exit``/``stderr``
    (stderr archived, the gate is the stable exit-4 Unusable
    contract). The aggregate leg is the refusal leg's positive
    control; its skcipher half also proves the promoted
    fixture's skcipher path on the floor kernel.
    """
    checks = {}
    checks["hash_exact"] = (
        aggregate.get("hash_observed") == aggregate.get("hash_issued")
    )
    checks["skcipher_exact"] = (
        aggregate.get("skc_enc_observed") == aggregate.get("skc_issued")
        and aggregate.get("skc_dec_observed") == aggregate.get("skc_issued")
    )
    checks["aggregate_lossless"] = aggregate.get("ring_drops") == "0"
    checks["aggregate_nonempty"] = (aggregate.get("hash_issued") or 0) > 0
    checks["refusal_exit_unusable"] = refusal.get("exit") == EXIT_UNUSABLE
    detail = {
        "hash": aggregate.get("hash_observed"),
        "skc_enc": aggregate.get("skc_enc_observed"),
        "skc_dec": aggregate.get("skc_dec_observed"),
        "refusal_exit": refusal.get("exit"),
    }
    return checks, detail


def check_r02(workload: dict, kernel_ref: dict, product: dict,
              quiet_before: dict, quiet_after: dict) -> tuple[dict, dict]:
    """R02 dm-crypt: workload integrity + kernel-equality + byte proof.

    ``workload`` carries ``bytes_written``/``bytes_read``/
    ``checksums_match``; ``kernel_ref`` the ftrace
    encrypt/decrypt invocation counts; ``product`` the observed
    encrypt/decrypt counts, observed ``enc_bytes``/``dec_bytes``
    totals and ``ring_drops``; quiet windows carry background
    ``product_rows``/``kernel_hits``. Bytes are NEVER equated to
    calls: the relation needs exact bytes AND exact calls AND
    the explained uniform chunking (both direction quotients
    integral, equal, and dividing the 4 KiB block).
    """
    checks = {}
    written = workload.get("bytes_written")
    read = workload.get("bytes_read")
    checks["workload_complete"] = written == read and (written or 0) > 0
    checks["workload_integral"] = workload.get("checksums_match") is True
    enc_k, dec_k = kernel_ref.get("skcipher_encrypt"), kernel_ref.get("skcipher_decrypt")
    checks["kernel_traffic_proved"] = (enc_k or 0) > 0 and (dec_k or 0) > 0
    enc_p, dec_p = product.get("skcipher_encrypt"), product.get("skcipher_decrypt")
    checks["calls_equal_kernel"] = enc_p == enc_k and dec_p == dec_k
    checks["product_lossless"] = product.get("ring_drops") == "0"
    enc_b, dec_b = product.get("enc_bytes"), product.get("dec_bytes")
    checks["bytes_reconcile"] = (
        enc_b is not None and dec_b is not None
        and enc_b + dec_b == (written or 0) + (read or 0)
    )
    chunk = 0
    if (enc_p or 0) > 0 and (dec_p or 0) > 0 and enc_b is not None and dec_b is not None:
        if enc_b % enc_p == 0 and dec_b % dec_p == 0:
            quotient_enc, quotient_dec = enc_b // enc_p, dec_b // dec_p
            if quotient_enc == quotient_dec:
                chunk = quotient_enc
    checks["chunking_explained"] = chunk > 0 and 4096 % chunk == 0
    checks["quiet_bounded"] = all(
        window.get("product_rows") == 0 and window.get("kernel_hits") == 0
        for window in (quiet_before, quiet_after)
    )
    detail = {
        "bytes": (written or 0) + (read or 0),
        "calls": (enc_k or 0) + (dec_k or 0),
        "chunk_bytes": chunk,
    }
    return checks, detail


def check_r03(ledger_a: dict, ledger_b: dict, kernel_ref: dict, product: dict,
              authfail_ledger: dict, authfail_product: dict,
              quiet_before: dict, quiet_after: dict) -> tuple[dict, dict]:
    """R03 XFRM ESP: packet ledgers + kernel-equality + auth-fail phase.

    ``ledger_a``/``ledger_b`` carry per-direction ``sent``/
    ``received``; ``kernel_ref`` the ftrace AEAD counts;
    ``product`` the observed AEAD counts; the authfail pair
    carries the controlled-failure phase (100 sent, 0 received,
    exact decrypt errors with native errnos). Packet totals are
    contextual: product calls must equal the KERNEL reference,
    never the packet ledger.
    """
    checks = {}
    sent = (ledger_a.get("sent") or 0) + (ledger_b.get("sent") or 0)
    received = (ledger_a.get("received") or 0) + (ledger_b.get("received") or 0)
    checks["ledgers_lossless"] = sent == received and sent > 0
    enc_k, dec_k = kernel_ref.get("aead_encrypt"), kernel_ref.get("aead_decrypt")
    checks["kernel_traffic_proved"] = (enc_k or 0) > 0 and (dec_k or 0) > 0
    checks["calls_equal_kernel"] = (
        product.get("aead_encrypt") == enc_k and product.get("aead_decrypt") == dec_k
    )
    checks["product_lossless"] = product.get("ring_drops") == "0"
    checks["authfail_exact"] = (
        (authfail_ledger.get("sent") or 0) == 100
        and (authfail_ledger.get("received") or 0) == 0
        and (authfail_product.get("aead_decrypt_errors") or 0) == 100
    )
    errnos = authfail_product.get("error_errnos") or []
    checks["authfail_errno_native"] = len(errnos) > 0 and all(
        isinstance(code, int) and code < 0 for code in errnos
    )
    checks["quiet_bounded"] = all(
        window.get("product_rows") == 0 and window.get("kernel_hits") == 0
        for window in (quiet_before, quiet_after)
    )
    detail = {"packets": sent, "aead_calls": (enc_k or 0) + (dec_k or 0)}
    return checks, detail


def check_r04_deny(refusal: dict, control: dict) -> tuple[dict, dict]:
    """R04 denied-attach: typed refusal + exact positive control.

    ``refusal`` carries ``exit``/``stderr`` (gate: stable exit-4
    Unusable); ``control`` carries ``issued``/``observed``/
    ``ring_drops`` of the privileged aggregate leg on the same
    kernel.
    """
    checks = {}
    checks["refusal_exit_unusable"] = refusal.get("exit") == EXIT_UNUSABLE
    checks["control_exact"] = control.get("observed") == control.get("issued")
    checks["control_lossless"] = control.get("ring_drops") == "0"
    checks["control_nonempty"] = (control.get("issued") or 0) > 0
    detail = {
        "refusal_exit": refusal.get("exit"),
        "control": control.get("observed"),
    }
    return checks, detail


def check_r04_foreign(owned: dict, foreign: dict, product_rows: list) -> tuple[dict, dict]:
    """R04 foreign traffic: unique owned correspondence, no absorption.

    ``owned``/``foreign`` carry ``pids`` + ``expected`` counts;
    ``product_rows`` are who rows (``tgid`` + ``calls``). Owned
    rows must match exactly over owned PIDs only; foreign rows
    must exist (the decoy ran) and stay excluded; any
    unattributed row fails.
    """
    checks = {}
    owned_pids = set(owned.get("pids") or [])
    foreign_pids = set(foreign.get("pids") or [])
    owned_matched = sum(
        row.get("calls", 0) for row in product_rows if row.get("tgid") in owned_pids
    )
    foreign_matched = sum(
        row.get("calls", 0) for row in product_rows if row.get("tgid") in foreign_pids
    )
    unattributed = [
        row for row in product_rows
        if row.get("tgid") not in owned_pids and row.get("tgid") not in foreign_pids
    ]
    checks["owned_exact"] = owned_matched == owned.get("expected")
    checks["foreign_present"] = foreign_matched == foreign.get("expected")
    checks["foreign_excluded"] = bool(foreign_pids) and not (owned_pids & foreign_pids)
    checks["no_unattributed_rows"] = not unattributed
    detail = {
        "owned_matched": owned_matched,
        "foreign_matched": foreign_matched,
        "unattributed": len(unattributed),
    }
    return checks, detail
