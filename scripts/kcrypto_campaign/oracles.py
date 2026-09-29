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

# Hash-only traffic contract for the R04 foreign cell: the only
# submitter probes the scenario can legitimately produce (outer
# ahash digest, nested shash digest/finup, one bind-alloc per
# burst). Anything else fails closed in the oracle, never here.
FOREIGN_PROBES = frozenset({"ahash", "shash", "finup", "alloc"})


class OracleError(ValueError):
    """Oracle input refusal: the archived facts are not the pinned shape."""


def who_probe_from_stack(payload: dict) -> str | None:
    """Name the submitter probe family from a who row's stack.

    The first ``bpf_prog_<hash>_kcrypto_<name>`` frame names the
    probe (``ahash``/``shash``/``finup``/``alloc``). Rows without
    a stack (or without a kcrypto frame) yield ``None``: the
    parser stays total and the oracle fails closed.
    """
    stack = payload.get("stack") or {}
    frames = stack.get("frames") or []
    for frame in frames:
        sym = (frame or {}).get("sym") or ""
        if not sym.startswith("bpf_prog_"):
            continue
        _head, sep, tail = sym.partition("_kcrypto_")
        if sep and tail:
            return tail
    return None


def parse_api_returns_report(doc: dict) -> dict:
    """Parse a pinned ``report --system --format json`` document.

    Returns ``{"agg": {(family, op, result, algorithm, driver,
    context): {"calls", "errors", "ok", "queued", "bytes"}},
    "who": [{tgid, tid, comm, uid, calls, first_errno, probe}],
    "totals": {...}, "loss": {"ring_drops", "ktot_gap",
    ...integrity counters}, "attach": {"probes_attached",
    "probes_expected"}, "verdict": {...},
    "duplicates_collapsed": n}``. The agg key carries the full
    row identity: the same (family, op, result) legitimately
    repeats per algorithm/driver (e.g. three ``any/alloc/ok``
    rows for cbc(aes), cryptd and sha256).
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
            key = (payload.get("family"), payload.get("op"), payload.get("result"),
                   payload.get("algorithm"), payload.get("driver"),
                   payload.get("context"))
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
                    "probe": who_probe_from_stack(payload),
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
    attach: dict[str, str] = {}
    coverage = doc["coverage"]
    if not isinstance(coverage, dict):
        raise OracleError("report 'coverage' must be an object")
    for dim in ("aggregate_counts", "detailed_events", "attachment"):
        counters = coverage.get(dim, {}).get("counters", [])
        for counter in counters:
            if isinstance(counter, dict) and "name" in counter:
                if dim == "attachment":
                    attach[counter["name"]] = counter.get("value")
                else:
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
        "attach": attach,
        "verdict": doc["verdict"],
        "duplicates_collapsed": duplicates,
    }


def _zero_loss(loss: dict, *names: str) -> bool:
    return all(loss.get(name) == "0" for name in names)


def check_r01_det(leg_a: dict, leg_b: dict) -> tuple[dict, dict]:
    """R01 deterministic fixture legs: identical semantic counts twice.

    Each leg carries ``ledger_ops`` (fixture truth), ``ledger_rc``
    (strict testkit validation exit), ``attach_markers`` (proven
    observer attach count), ``product`` (observed per-family
    counts), ``fixture_truth`` (per-op counts the ledger rows
    issue) and ``observed_by_op`` (per-op counts the product
    observed, every family reported). Determinism = exact
    equality of every semantic count across both legs with both
    ledgers valid — AND each leg's observation must equal the
    fixture truth it was issued: repeatability alone would
    certify two empty observations.
    """
    checks = {}
    checks["ledgers_valid"] = leg_a.get("ledger_rc") == 0 and leg_b.get("ledger_rc") == 0
    checks["attach_proved"] = bool(leg_a.get("attach_markers")) and bool(
        leg_b.get("attach_markers")
    )
    checks["ledger_deterministic"] = leg_a.get("ledger_ops") == leg_b.get("ledger_ops")
    checks["deterministic_counts"] = leg_a.get("product") == leg_b.get("product")
    checks["legA_matches_truth"] = (
        leg_a.get("observed_by_op") == leg_a.get("fixture_truth")
        and bool(leg_a.get("fixture_truth"))
    )
    checks["legB_matches_truth"] = (
        leg_b.get("observed_by_op") == leg_b.get("fixture_truth")
        and bool(leg_b.get("fixture_truth"))
    )
    detail = {
        "ledger_ops": leg_a.get("ledger_ops"),
        "product": leg_a.get("product"),
        "fixture_truth": leg_a.get("fixture_truth"),
    }
    return checks, detail


def check_r01_floor(workload: dict, kernel_ref: dict, product: dict,
                   refusal: dict) -> tuple[dict, dict]:
    """R01 6.12 floor: supported aggregate exact + lifecycle refusal typed.

    ``workload`` carries ``hash_issued``/``hash_done``/
    ``skc_issued``/``skc_done`` (fixture truth); ``kernel_ref``
    the ftrace per-function counts; ``product`` the observed
    per-function counts + ``ring_drops``; ``refusal`` carries
    ``exit``/``stderr`` (gate: stable exit-4 Unusable). Product
    must equal the KERNEL reference exactly on every traced
    function; the documented 6.12 routes are gated separately
    at the kernel level. The outer ahash call is 1:1 with
    issued digests on every run; the NESTED route is
    scatterlist-shaped (page layout per burst) and takes
    exactly one admitted arm: one shash digest per digest
    (T07 precedent), one shash finup per digest, or two
    finups per digest on split scatterlists. Skcipher keeps
    one outer + one cryptd-nested inner call per op (2x
    issued). The aggregate leg is the refusal leg's positive
    control.
    """
    checks = {}
    checks["workload_proved"] = (
        workload.get("hash_done") == workload.get("hash_issued")
        and workload.get("skc_done") == workload.get("skc_issued")
        and (workload.get("hash_issued") or 0) > 0
    )
    checks["hash_kernel_equal"] = (
        product.get("ahash_digest") == kernel_ref.get("ahash_digest")
        and product.get("shash_digest") == kernel_ref.get("shash_digest")
        and product.get("shash_finup") == kernel_ref.get("shash_finup")
    )
    checks["skcipher_kernel_equal"] = (
        product.get("skcipher_encrypt") == kernel_ref.get("skcipher_encrypt")
        and product.get("skcipher_decrypt") == kernel_ref.get("skcipher_decrypt")
    )
    checks["kernel_nonempty"] = (
        (kernel_ref.get("ahash_digest") or 0) > 0
        and ((kernel_ref.get("shash_digest") or 0) > 0
             or (kernel_ref.get("shash_finup") or 0) > 0)
        and (kernel_ref.get("skcipher_encrypt") or 0) > 0
        and (kernel_ref.get("skcipher_decrypt") or 0) > 0
    )
    issued = workload.get("hash_issued")
    digest = kernel_ref.get("shash_digest")
    finup = kernel_ref.get("shash_finup")
    if digest == issued and finup == 0:
        nested_route = "digest-1x"
    elif digest == 0 and finup == issued:
        nested_route = "finup-1x"
    elif digest == 0 and finup == 2 * (issued or 0):
        nested_route = "finup-2x"
    else:
        nested_route = "undocumented"
    checks["hash_route_documented"] = (
        kernel_ref.get("ahash_digest") == issued
        and nested_route != "undocumented"
    )
    checks["skcipher_route_documented"] = (
        kernel_ref.get("skcipher_encrypt") == 2 * (workload.get("skc_issued") or 0)
        and kernel_ref.get("skcipher_decrypt") == 2 * (workload.get("skc_issued") or 0)
    )
    checks["product_lossless"] = product.get("ring_drops") == "0"
    checks["refusal_exit_unusable"] = refusal.get("exit") == EXIT_UNUSABLE
    detail = {
        "kernel": dict(kernel_ref),
        "product": {k: product.get(k) for k in kernel_ref},
        "nested_route": nested_route,
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
    calls and NEVER pooled across directions: the relation needs
    exact per-direction bytes (encrypt vs written, decrypt vs
    read) AND exact calls AND the integral-average chunking
    shape (both direction quotients integral, equal, and
    dividing the 4 KiB block). The chunking gate proves the
    average request size is consistent with uniform 512 B
    chunking — an integral average alone proves nothing about
    per-request uniformity, so the byte proof rests on the
    per-direction equalities, never on the average.
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
        and enc_b == written and dec_b == read
    )
    chunk = 0
    quotient_enc = quotient_dec = 0
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
        "quotient_enc": quotient_enc,
        "quotient_dec": quotient_dec,
    }
    return checks, detail


# Scenario-fixed XFRM SA identities (r03_xfrm.sh installs exactly
# these two SAs per namespace): (src, dst, spi).
XFRM_SA_AB = ("10.13.0.1", "10.13.0.2", 4097)
XFRM_SA_BA = ("10.13.0.2", "10.13.0.1", 4098)


def _xfrm_file_has_exact_sas(facts) -> bool:
    sas = (facts or {}).get("sas") or {}
    return set(sas) == {XFRM_SA_AB, XFRM_SA_BA}


def _xfrm_sa_ok(sas, key, packets: int, failed: int = 0,
               replay: int = 0, replay_window: int = 0) -> bool:
    sa = (sas or {}).get(key)
    if not isinstance(sa, dict):
        return False
    return (sa.get("packets") == packets and sa.get("failed") == failed
            and sa.get("replay") == replay
            and sa.get("replay_window") == replay_window)


def check_r03(ledger_a: dict, ledger_b: dict, kernel_ref: dict, product: dict,
              authfail_ledger: dict, authfail_product: dict,
              quiet_before: dict, quiet_after: dict,
              xfrm: dict) -> tuple[dict, dict]:
    """R03 XFRM ESP: packet ledgers + kernel-equality + auth-fail phase.

    ``ledger_a``/``ledger_b`` carry per-direction ``sent``/
    ``received`` plus the receiver sequence accounting
    (``missing_total``/``duplicates_total``); ``kernel_ref`` the
    ftrace AEAD counts; ``product`` the observed AEAD counts;
    the authfail pair carries the controlled-failure phase (100
    sent, 0 received) plus its own kernel counts; ``xfrm``
    carries the archived state count plus the per-namespace
    packet/error-counter ledgers (``main_a``/``main_b``/
    ``authfail_a``/``authfail_b`` SA facts). Packet totals are
    contextual: product calls must equal the KERNEL reference,
    never the packet ledger -- including the failure phase,
    where the ESP echainiv nesting fails at both levels (200
    errors for 100 packets): observed errors must equal kernel
    decrypts, observed ok-decrypts must be zero, encrypts
    kernel-equal. Sequence totals must account exactly (a
    duplicate substituting for a missing sequence fails), both
    SAs must exist, and the XFRM counters must show the
    delivered packets with zero main-phase errors and exactly
    the 100 wrong-key failures on the rekeyed SA. The stats
    ``replay-window`` error counter must read zero on every SA
    (P8-N11), like ``replay``/``failed``.
    """
    checks = {}
    sent = (ledger_a.get("sent") or 0) + (ledger_b.get("sent") or 0)
    received = (ledger_a.get("received") or 0) + (ledger_b.get("received") or 0)
    checks["ledgers_lossless"] = sent == received and sent > 0
    checks["sequence_exact"] = all(
        ledger.get("missing_total")
        == (ledger.get("sent") or 0) - (ledger.get("received") or 0)
        and ledger.get("duplicates_total") == 0
        for ledger in (ledger_a, ledger_b)
    )
    enc_k, dec_k = kernel_ref.get("aead_encrypt"), kernel_ref.get("aead_decrypt")
    checks["kernel_traffic_proved"] = (enc_k or 0) > 0 and (dec_k or 0) > 0
    checks["calls_equal_kernel"] = (
        product.get("aead_encrypt") == enc_k and product.get("aead_decrypt") == dec_k
    )
    checks["product_lossless"] = product.get("ring_drops") == "0"
    checks["authfail_exact"] = (
        (authfail_ledger.get("sent") or 0) == 100
        and (authfail_ledger.get("received") or 0) == 0
    )
    checks["authfail_sequence_exact"] = (
        authfail_ledger.get("missing_total")
        == (authfail_ledger.get("sent") or 0)
        - (authfail_ledger.get("received") or 0)
        and authfail_ledger.get("duplicates_total") == 0
    )
    xfrm = xfrm or {}
    checks["xfrm_state_exact"] = xfrm.get("state_count") == 2
    sent_a, sent_b = ledger_a.get("sent"), ledger_b.get("sent")
    sent_f = authfail_ledger.get("sent")
    main_a, main_b = xfrm.get("main_a"), xfrm.get("main_b")
    checks["xfrm_main_exact"] = (
        _xfrm_file_has_exact_sas(main_a)
        and _xfrm_file_has_exact_sas(main_b)
        and all(
            _xfrm_sa_ok(facts.get("sas"), key, expected)
            for facts, key, expected in (
                (main_a, XFRM_SA_AB, sent_a),
                (main_a, XFRM_SA_BA, sent_b),
                (main_b, XFRM_SA_AB, sent_a),
                (main_b, XFRM_SA_BA, sent_b),
            )
        )
    )
    auth_a, auth_b = xfrm.get("authfail_a"), xfrm.get("authfail_b")
    checks["xfrm_authfail_exact"] = (
        _xfrm_file_has_exact_sas(auth_a)
        and _xfrm_file_has_exact_sas(auth_b)
        and _xfrm_sa_ok(auth_a.get("sas"), XFRM_SA_AB,
                        (sent_a or 0) + (sent_f or 0))
        and _xfrm_sa_ok(auth_a.get("sas"), XFRM_SA_BA, sent_b)
        and _xfrm_sa_ok(auth_b.get("sas"), XFRM_SA_AB, 0,
                        failed=(sent_f or 0))
        and _xfrm_sa_ok(auth_b.get("sas"), XFRM_SA_BA, sent_b)
    )
    auth_kdec = authfail_product.get("kernel_decrypt")
    auth_kenc = authfail_product.get("kernel_encrypt")
    checks["authfail_counts_equal"] = (
        (auth_kdec or 0) > 0
        and (authfail_product.get("aead_decrypt_errors") or 0) == auth_kdec
        and (authfail_product.get("aead_decrypt") or 0) == 0
        and (authfail_product.get("aead_encrypt") or 0) == (auth_kenc or -1)
    )
    errnos = authfail_product.get("error_errnos") or []
    checks["authfail_errno_native"] = len(errnos) > 0 and all(
        isinstance(code, int) and code < 0 for code in errnos
    )
    checks["quiet_bounded"] = all(
        window.get("product_rows") == 0 and window.get("kernel_hits") == 0
        for window in (quiet_before, quiet_after)
    )
    detail = {"packets": sent, "aead_calls": (enc_k or 0) + (dec_k or 0),
              "xfrm_state_count": xfrm.get("state_count")}
    return checks, detail


def check_r04_deny(refusal: dict, control: dict, kernel_ref: dict) -> tuple[dict, dict]:
    """R04 denied-attach: typed refusal + exact positive control.

    ``refusal`` carries ``exit``/``stderr`` (gate: stable exit-4
    Unusable), ``expected_obj_sha`` (the staged BPF object pin)
    and ``unpriv_read_sha`` (the uid-65534 readability proof);
    ``control`` carries the privileged aggregate leg's
    ``hash_issued``/``hash_done``/per-function observed counts +
    ``ring_drops``; ``kernel_ref`` the ftrace per-function
    counts. The refusal must genuinely REACH the disabled hook:
    bare exit 4 is insufficient — the log must show the staged
    object loaded (audit line binding the exact staged bytes),
    the capability-gate denial, and no object-missing short
    circuit; the nobody readability proof must match the pin.
    Control product must equal the kernel reference exactly (no
    route assumption: the 7.x per-digest shape is RECORDED,
    supporting the support-table row — a genuinely unused
    function reads 0 on both sides, never a silent skip).
    """
    checks = {}
    stderr = refusal.get("stderr") or ""
    expected_sha = refusal.get("expected_obj_sha") or ""
    checks["refusal_exit_unusable"] = refusal.get("exit") == EXIT_UNUSABLE
    checks["refusal_shows_object_load"] = (
        '"audit":"object-load"' in stderr
        and bool(expected_sha)
        and f'"sha256":"{expected_sha}"' in stderr
    )
    checks["refusal_shows_capability_denial"] = "no BPF capability" in stderr
    checks["refusal_no_object_missing"] = "object missing" not in stderr
    checks["refusal_unpriv_read_proved"] = (
        bool(expected_sha)
        and (refusal.get("unpriv_read_sha") or "") == expected_sha
    )
    checks["control_workload_proved"] = (
        control.get("hash_done") == control.get("hash_issued")
        and (control.get("hash_issued") or 0) > 0
    )
    checks["control_kernel_equal"] = all(
        control.get("observed", {}).get(name) == kernel_ref.get(name)
        for name in kernel_ref
    ) and bool(kernel_ref)
    checks["control_nonempty"] = any(
        (kernel_ref.get(name) or 0) > 0 for name in kernel_ref
    ) and bool(kernel_ref)
    checks["control_lossless"] = control.get("ring_drops") == "0"
    detail = {
        "refusal_exit": refusal.get("exit"),
        "kernel": dict(kernel_ref),
        "observed": dict(control.get("observed", {})),
    }
    return checks, detail


def _nested_arm(outer: int, shash: int, finup: int) -> str:
    """Name the admitted nested arm for one burst population.

    One sendmsg nests exactly one admitted shape below the outer
    ahash call (digest-1x, finup-1x, or finup-2x — the
    scatterlist-shaped T13 arms); anything else (mixed arms,
    absent nesting, digest-2x) is undocumented and fails.
    """
    if (outer or 0) <= 0:
        return "undocumented"
    if shash == outer and finup == 0:
        return "digest-1x"
    if shash == 0 and finup == outer:
        return "finup-1x"
    if shash == 0 and finup == 2 * outer:
        return "finup-2x"
    return "undocumented"


def check_r04_foreign(owned_pids: list, foreign_pids: list, owned_issued: int,
                      foreign_issued: int, product_rows: list,
                      agg_all_total: int) -> tuple[dict, dict]:
    """R04 foreign traffic: unique owned correspondence, no absorption.

    Who rows (``tgid`` + ``probe`` + ``calls``) must attribute
    every observation to exactly the recorded owned/foreign PID
    sets. The issued counts (20 owned, 6 foreign) are proved as
    ABSOLUTE outer-ahash equalities per population: one sendmsg
    is one outer digest whatever the kernel's nested route, so a
    ratio alone cannot catch proportional loss (10:3 keeps the
    ratio against 20:6 receipts). The NESTED populations are
    gated per probe per population too: each burst takes exactly
    one admitted arm (digest-1x, finup-1x, finup-2x — the arms
    may differ between the owned and foreign bursts, never
    within one), so a nested call absorbed into the foreign
    population breaks the owned arm. Each burst binds exactly
    once, so the bind-alloc rows are pinned 1:1. Coverage is who
    over EVERY agg family (nested rows included, nothing
    unattributed, nothing absorbed).
    """
    checks = {}
    owned_set, foreign_set = set(owned_pids or []), set(foreign_pids or [])

    def matched(probe: str, pids: set) -> int:
        return sum(
            row.get("calls", 0) for row in product_rows
            if row.get("tgid") in pids and row.get("probe") == probe
        )

    owned_outer = matched("ahash", owned_set)
    foreign_outer = matched("ahash", foreign_set)
    owned_alloc = matched("alloc", owned_set)
    foreign_alloc = matched("alloc", foreign_set)
    owned_shash = matched("shash", owned_set)
    owned_finup = matched("finup", owned_set)
    foreign_shash = matched("shash", foreign_set)
    foreign_finup = matched("finup", foreign_set)
    owned_nested = owned_shash + owned_finup
    foreign_nested = foreign_shash + foreign_finup
    owned_arm = _nested_arm(owned_outer, owned_shash, owned_finup)
    foreign_arm = _nested_arm(foreign_outer, foreign_shash, foreign_finup)
    who_total = sum(row.get("calls", 0) for row in product_rows)
    unattributed = [
        row for row in product_rows
        if row.get("tgid") not in owned_set and row.get("tgid") not in foreign_set
    ]
    checks["pid_sets_disjoint"] = bool(owned_set) and bool(foreign_set) and not (
        owned_set & foreign_set
    )
    checks["probes_classified"] = all(
        row.get("probe") in FOREIGN_PROBES for row in product_rows
    ) and bool(product_rows)
    checks["ratio_exact"] = (
        owned_outer * (foreign_issued or 0) == foreign_outer * (owned_issued or 0)
        and (owned_issued or 0) > 0
        and (foreign_issued or 0) > 0
    )
    checks["owned_outer_exact"] = owned_outer == owned_issued
    checks["foreign_outer_exact"] = foreign_outer == foreign_issued
    checks["owned_nested_exact"] = owned_arm != "undocumented"
    checks["foreign_nested_exact"] = foreign_arm != "undocumented"
    checks["foreign_present"] = foreign_outer > 0
    checks["alloc_exact"] = owned_alloc == 1 and foreign_alloc == 1
    checks["coverage_exact"] = (
        who_total == agg_all_total
        and (agg_all_total or 0) > 0
    )
    checks["no_unattributed_rows"] = not unattributed
    detail = {
        "owned_outer": owned_outer,
        "foreign_outer": foreign_outer,
        "owned_alloc": owned_alloc,
        "foreign_alloc": foreign_alloc,
        "owned_nested": owned_nested,
        "foreign_nested": foreign_nested,
        "owned_shash": owned_shash,
        "owned_finup": owned_finup,
        "foreign_shash": foreign_shash,
        "foreign_finup": foreign_finup,
        "owned_nested_arm": owned_arm,
        "foreign_nested_arm": foreign_arm,
        "who_total": who_total,
        "agg_all_total": agg_all_total,
        "unattributed": len(unattributed),
    }
    return checks, detail
