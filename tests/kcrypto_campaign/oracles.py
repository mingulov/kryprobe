#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""P2 portion oracles: pure checker predicates over archived phase facts.

P2r repair wave: the checkers move out of the throwaway lane script
into this committed module so the reviewers' counterexamples pin them
as regression tests (``test_oracles.py``). Every function is pure
(dicts in, ``(checks, observation)`` out); the lane receipt builder
loads the archived files and calls these. ``receipt.verify`` gates on
the returned ``checks``/``oracle_failed`` (P2r/C4).

P2r2 repair (R1): the E07 map stage requires a POSITIVE non-hook-miss
residual (``state_insert - prog_miss > 0``) — the product composite
cannot isolate map-table failures further, so this is the exact
honesty bound — and the gap cover counts each hook miss once (the P2r
cover double-counted the folded ``prog_miss``). The ``fold_consistent``
guard fails closed if the product ever stops folding.

P2r repair (C1, C2): E07 expected counts derive from independent
issued/ledger counts (never product admissions); each stage carries
an exact arrival equation plus a gap-coverage inequality over named
loss buckets (tolerance 0), and stage PASS requires its NAMED
integrity counter nonzero. E05 active cases use an exact
signal-time ledger snapshot equation
(``product == pre_SIGINT + tail``, ``0 <= tail <= post_before_exit``)
with zero-transport-loss proof; the closing gate is narrowed to the
executed stop-after-completion stimulus (mid-drain stop unproved).
The P2b predicates these replace lived in
lane-p2b-01/make-receipts.py:189,229,245.
"""

from __future__ import annotations

# Measured fresh-burst shape constant: every fresh ECB op emits
# exactly 8 lifecycle edges. Exact (tolerance 0) on all 10 preserved
# fresh-burst runs: accepted + prog_miss_delta == 8 * issued holds
# for E01a x2, E03 x2, E06 x2, E07-ring x2, E07-user x2 (p2b raw).
# Retained-TFM shapes (E02) emit ~2 edges/op and never use this.
FRESH_EDGES_PER_OP = 8

# E07 stage -> the integrity counter that must independently prove
# that stage's overload (P2r/C1). The product loss taxonomy
# (backend.rs integrity_for_lifecycle): kernel reserve failures ->
# ring; refused/record evidence incl. prog-miss deltas -> state
# inserts; retention drops past the ledger bound -> user queue.
NAMED_COUNTER = {
    "ring": "ring_reservation_failures",
    "map": "state_insert_failures",
    "user": "user_queue_drops",
}

# RSS bound shared by the overload/stop oracles (envelope-wide).
RSS_BOUND_BYTES = 512 * 1024**2


def check_totals(r: dict, oracle: str) -> tuple[dict, dict]:
    """Totals oracle over one observed-totals phase-result dict (E01a/E02/E03)."""
    c = r["coverage"]
    checks = {}
    checks["worker_ok"] = r["worker_wait"]["ok"] is True
    checks["cli_exit_partial"] = r["cli_exit"] == 3
    checks["no_cli_timeout"] = r["cli_timed_out"] is False
    checks["ledger_exact"] = r["actual"] == r["expected"]
    checks["observations_exact"] = r["observations"] == r["expected"]
    checks["distinct_exact"] = r["distinct_request_ids"] == r["expected"]
    checks["admitted_exact"] = int(c["aggregate_counts"]["submits_admitted"]) == r["expected"]
    checks["zero_count_loss"] = c["aggregate_counts"]["count_loss"] == "0"
    checks["zero_prog_miss"] = c["aggregate_counts"]["prog_miss_delta"] == "0"
    checks["zero_ring_drops"] = c["detailed_events"]["ring_drops"] == "0"
    checks["agg_consumed_eq_accepted"] = (c["detailed_events"]["agg_accepted"]
                                         == c["detailed_events"]["agg_consumed"])
    checks["zero_residual"] = c["detailed_events"]["agg_residual_unexplained"] == "0"
    checks["zero_unknown_trunc_unfin"] = all(
        c["completion"][k] == "0" for k in
        ("unknown_terminals", "observations_truncated", "unfinished_truthless"))
    checks["verdict_partial_attribution"] = (
        r["verdict"]["status"] == "partial"
        and "attribution" in r["verdict"]["missing"])
    checks["reaped"] = r["cli_reaped"] and r["worker_reaped"]
    observation = {"expected": r["expected"], "actual": r["observations"],
                   "ledger_completed": r["actual"],
                   "distinct_request_ids": r["distinct_request_ids"],
                   "cli_exit": r["cli_exit"], "output_bytes": r["output_bytes"],
                   "observer": r["observer"],
                   "attach_ready_latency_s": r.get("attach_ready_latency_s"),
                   "verdict": r["verdict"], "coverage": r["coverage"]}
    if "schedule" in r:
        observation["schedule"] = r["schedule"]
    return checks, {"observation": observation, "oracle": oracle}


def check_cap(r: dict) -> tuple[dict, dict]:
    """Cap oracle over one observed-totals phase-result dict (E06)."""
    c = r["coverage"]
    kept = r["observations"]
    trunc = int(c["completion"]["observations_truncated"])
    admitted = int(c["aggregate_counts"]["submits_admitted"])
    checks = {}
    checks["worker_ok"] = r["worker_wait"]["ok"] is True
    checks["cli_exit_partial"] = r["cli_exit"] == 3
    checks["no_cli_timeout"] = r["cli_timed_out"] is False
    checks["admitted_all_issued"] = admitted == r["expected"] == 100005
    checks["kept_is_cap"] = kept == 100000
    checks["truncated_plus_kept_eq_admitted"] = kept + trunc == admitted
    checks["truncated_is_5"] = trunc == 5
    checks["distinct_is_cap"] = r["distinct_request_ids"] == 100000
    checks["zero_ring_drops"] = c["detailed_events"]["ring_drops"] == "0"
    checks["agg_closed"] = (c["detailed_events"]["agg_accepted"]
                            == c["detailed_events"]["agg_consumed"]
                            == str(100005 * 8))
    checks["zero_residual"] = c["detailed_events"]["agg_residual_unexplained"] == "0"
    checks["zero_unknown_unfin"] = all(
        c["completion"][k] == "0" for k in
        ("unknown_terminals", "unfinished_truthless"))
    checks["completion_missing_explicit"] = "completion" in r["verdict"]["missing"]
    checks["rss_bounded"] = r["observer"]["observer_peak_rss_bytes"] < 512 * 1024**2
    checks["reaped"] = r["cli_reaped"] and r["worker_reaped"]
    observation = {"expected": admitted, "actual": kept + trunc,
                   "issued": r["expected"], "ledger_completed": r["actual"],
                   "admitted": admitted, "retained": kept, "truncated": trunc,
                   "cli_exit": r["cli_exit"], "output_bytes": r["output_bytes"],
                   "observer": r["observer"], "verdict": r["verdict"],
                   "coverage": r["coverage"]}
    oracle = ("E06: literal 100,000 boundary; truncated/retained/"
              "unfinished reconcile; product explicit partial")
    return checks, {"observation": observation, "oracle": oracle}


def check_stop_case(gate: str, rep: int, case: dict, snapshot: dict | None,
                    product: dict | None) -> tuple[bool, dict]:
    """E05 single-case equation (P2r/C2: exact snapshot equation).

    ``case`` is one phase-result ``cases[]`` entry; ``snapshot`` (active
    gate only) carries ``pre_sigint`` (ledger rows completed at or
    before SIGINT-send) and ``post_before_exit`` (rows completed after
    SIGINT-send but before CLI exit — the principled tail cap);
    ``product`` (active gate only) carries the case report's
    ``coverage``/``integrity``. Returns (equation_ok, detail).
    """
    base_ok = bool(case["ok"] and case["cli_exit"] == 3
                   and not case["cli_timed_out"]
                   and case["stop_latency_s"] <= 10)
    detail = {"gate": gate, "rep": rep, "equation_ok": False,
              "cli_exit": case["cli_exit"],
              "stop_latency_s": case["stop_latency_s"],
              "ledger": case["ledger_completed"],
              "product_obs": case.get("product_observations"),
              "output_bytes": case["output_bytes"]}
    if gate == "before-GO":
        eq = case["ledger_completed"] == 0 and case["product_observations"] == 0
    elif gate == "closing-drain":
        # Narrowed to the executed stimulus: SIGINT after the workers
        # reaped + 0.5 s (stop-after-completion of the frozen
        # burst-1000 cell, hash-bound in stage.json). A backlogged
        # mid-drain SIGINT is NOT demonstrated here — open, see the
        # oracle string.
        eq = case["ledger_completed"] == 1000 and case["product_observations"] == 1000
    elif gate == "active-burst":
        if snapshot is None or product is None:
            raise ValueError("active-burst needs the signal-time snapshot + product report")
        pre = snapshot["pre_sigint"]
        cap = snapshot["post_before_exit"]
        prod = case["product_observations"]
        tail = prod - pre
        cov = product["coverage"]
        integ = product["integrity"]
        # Zero transport loss in THIS case's report: every pre-SIGINT
        # completion must have been drained, so the count equation is
        # sound (no hidden pre-SIGINT loss masquerading as tail).
        zero_loss = all([
            cov["detailed_events"]["ring_drops"] == "0",
            cov["aggregate_counts"]["prog_miss_delta"] == "0",
            cov["detailed_events"]["agg_residual_unexplained"] == "0",
            cov["completion"]["unfinished_truthless"] == "0",
            cov["completion"]["unknown_terminals"] == "0",
            cov["completion"]["observations_truncated"] == "0",
            integ["budget_omissions"] == "0",
        ])
        admitted_eq_obs = (int(cov["aggregate_counts"]["submits_admitted"]) == prod)
        eq = tail >= 0 and tail <= cap and zero_loss and admitted_eq_obs
        detail.update({"pre_sigint": pre, "tail": tail, "tail_cap": cap,
                       "zero_transport_loss": zero_loss,
                       "admitted_eq_obs": admitted_eq_obs})
    else:
        raise ValueError(f"unknown gate {gate!r}")
    detail["equation_ok"] = bool(base_ok and eq)
    return detail["equation_ok"], detail


def check_overload_stage(name: str, s: dict, integrity: dict | None) -> tuple[bool, dict]:
    """E07 single-stage equation (P2r/C1: reconciled, named-counter).

    ``s`` is one phase-result ``stages[]`` entry (fresh-burst stimulus
    only — the exact arrival equation needs the measured 8-edges/op
    shape); ``integrity`` is the stage report's integrity counters.
    Expected counts come from independent issued/ledger counts, never
    product admissions. Returns (equation_ok, detail) with the
    per-predicate ``checks`` inside the detail for receipt rollup.
    """
    if name not in NAMED_COUNTER:
        raise ValueError(f"unknown overload stage {name!r}")
    if not isinstance(integrity, dict):
        raise ValueError("E07 stage needs its report integrity counters")
    c = s["coverage"]
    issued = s["expected"]
    ledger = s["actual"]
    obs = s["observations"]
    admitted = int(c["aggregate_counts"]["submits_admitted"])
    prog_miss = int(c["aggregate_counts"]["prog_miss_delta"])
    ring_drops = int(c["detailed_events"]["ring_drops"])
    accepted = int(c["detailed_events"]["agg_accepted"])
    consumed = int(c["detailed_events"]["agg_consumed"])
    state_insert = int(integrity["state_insert_failures"])
    unmatched = int(integrity["unmatched_entries"]) + int(integrity["unmatched_returns"])
    overflows = int(integrity["correlation_overflows"])
    budget = int(integrity["budget_omissions"])
    user_drops = int(integrity["user_queue_drops"])
    named = int(integrity[NAMED_COUNTER[name]])
    gap = issued - obs
    # Every unobserved op lost at least one edge (ring drop or hook
    # miss) or landed in a counted refused/retained/unmatched/omitted
    # bucket; the product's closed transport equation (residual 0)
    # leaves no other path. Tolerance 0: the inequality is exact.
    #
    # P2r2/R1: state_insert_failures already folds prog_miss_delta
    # (backend.rs integrity_for_lifecycle saturating-adds
    # prog_miss_delta_sum), so the cover counts each hook miss ONCE,
    # inside state_insert — the P2r cover added prog_miss a second
    # time and let gap <= cover pass on double count. `fold_consistent`
    # below pins the fold assumption: if the product ever stops
    # folding, the oracle fails closed instead of under-counting.
    cover = (ring_drops + state_insert + user_drops
             + unmatched + overflows + budget)
    # P2r2/R1: the non-hook-miss residual inside the composite. The
    # product composite cannot isolate map-table failures further, so
    # a POSITIVE residual is the exact honesty bound for map overload:
    # residual > 0 proves failures beyond hook misses; residual == 0
    # (all four preserved map runs) proves nothing map-specific.
    map_residual = state_insert - prog_miss
    checks = {}
    checks["worker_ok"] = s["worker_wait"]["ok"] is True
    checks["cli_exit_partial"] = s["cli_exit"] == 3
    checks["no_cli_timeout"] = s["cli_timed_out"] is False
    checks["ledger_exact"] = ledger == issued
    checks["arrival_exact"] = FRESH_EDGES_PER_OP * issued == accepted + prog_miss
    checks["transport_closed"] = (accepted == consumed + ring_drops
                                  and c["detailed_events"]["agg_residual_unexplained"] == "0")
    checks["ring_counter_agrees"] = ring_drops == int(integrity["ring_reservation_failures"])
    checks["gap_nonnegative"] = gap >= 0
    checks["gap_covered"] = gap <= cover
    checks["named_counter_nonzero"] = named > 0
    checks["fold_consistent"] = state_insert >= prog_miss
    if name == "map":
        checks["map_residual_positive"] = map_residual > 0
    checks["rss_bounded"] = s["observer"]["observer_peak_rss_bytes"] < RSS_BOUND_BYTES
    checks["verdict_partial"] = s["verdict"]["status"] == "partial"
    checks["reaped"] = bool(s["cli_reaped"] and s["worker_reaped"])
    ok = all(checks.values())
    detail = {"stage": name, "equation_ok": ok, "issued": issued,
              "ledger_completed": ledger, "admitted": admitted,
              "observed": obs, "gap": gap, "loss_cover": cover,
              "named_counter": NAMED_COUNTER[name], "named_value": named,
              "ring_drops": ring_drops, "prog_miss_delta": prog_miss,
              "state_insert_failures": state_insert,
              "map_residual": map_residual,
              "peak_rss": s["observer"]["observer_peak_rss_bytes"],
              "cli_exit": s["cli_exit"], "checks": checks}
    return ok, detail
