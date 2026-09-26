#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Committed tests for the P2 portion oracles (P2r/C1, C2, C4).

Standard library only; no guests, no privilege. Run from this
directory::

    python3 -B -m unittest -v test_oracles

The negative tests are the reviewers' in-memory counterexamples made
durable: 3-obs/38000-issued E07, 1-obs E05 active cases, and the
ring_drops=1 E01a-shaped receipt. All go RED against the P2b checker
predicates (ported verbatim into ``oracles.py`` first) and GREEN after
the repair — see the P2r report for both logs.
"""

import unittest

import oracles
import receipt


def coverage(admitted, prog_miss=0, ring_drops=0, accepted=None, consumed=None,
             residual="0", count_loss="0", unknown="0", truncated="0",
             unfinished="0"):
    accepted = str(admitted * 8) if accepted is None else str(accepted)
    consumed = accepted if consumed is None else str(consumed)
    return {
        "aggregate_counts": {
            "submits_admitted": str(admitted),
            "prog_miss_delta": str(prog_miss),
            "count_loss": str(count_loss),
        },
        "detailed_events": {
            "ring_drops": str(ring_drops),
            "agg_accepted": accepted,
            "agg_consumed": consumed,
            "agg_residual_unexplained": str(residual),
        },
        "completion": {
            "unknown_terminals": str(unknown),
            "observations_truncated": str(truncated),
            "unfinished_truthless": str(unfinished),
        },
    }


def stage_result(issued, ledger, obs, cov, cli_exit=3, rss=80 * 1024**2):
    return {
        "expected": issued, "actual": ledger, "observations": obs,
        "coverage": cov, "cli_exit": cli_exit, "cli_timed_out": False,
        "worker_wait": {"ok": True}, "cli_reaped": True, "worker_reaped": True,
        "observer": {"observer_peak_rss_bytes": rss},
        "verdict": {"status": "partial", "missing": ["attribution"]},
    }


def integrity(ring=0, state=0, user=0, unmatched_e=0, unmatched_r=0,
              corr=0, budget=0):
    return {
        "ring_reservation_failures": str(ring),
        "state_insert_failures": str(state),
        "user_queue_drops": str(user),
        "unmatched_entries": str(unmatched_e),
        "unmatched_returns": str(unmatched_r),
        "correlation_overflows": str(corr),
        "budget_omissions": str(budget),
    }


def stop_case(gate, ledger, product, latency=0.2):
    return {"gate": gate, "ok": True, "cli_exit": 3, "cli_timed_out": False,
            "stop_latency_s": latency, "ledger_completed": ledger,
            "product_observations": product, "output_bytes": 1000}


class E07CounterexampleTests(unittest.TestCase):
    def test_three_obs_from_38000_issued_fails(self):
        # Reviewers' mutation: one observation/admission per stage, one
        # missed-hook count per stage — 3 observations from 38000
        # issued. The P2b checker returned PASS.
        stages = [("ring", 20000), ("map", 2000), ("user", 16000)]
        oks = []
        for name, issued in stages:
            cov = coverage(1, prog_miss=1)
            s = stage_result(issued, issued, 1, cov)
            ok, detail = oracles.check_overload_stage(name, s, integrity())
            oks.append(ok)
            self.assertEqual(detail["gap"], issued - 1)
        self.assertFalse(all(oks),
                         "3 observations from 38000 issued must not pass")

    def test_zero_named_counter_fails_each_stage(self):
        # Stage PASS requires its NAMED counter nonzero, even when every
        # other predicate holds (the p2b E07 shape: ring stage with 0
        # ring failures, map with 0 state-insert, user all zero).
        shapes = [
            ("ring", 20000, 19992, coverage(19992, prog_miss=50,
                                           accepted=159950, consumed=159950),
             integrity(ring=0, state=50)),
            ("map", 2000, 2000, coverage(2000, ring_drops=1130,
                                         accepted=40000, consumed=38870),
             integrity(ring=1130, state=0)),
            ("user", 16000, 16000, coverage(16000, accepted=128000,
                                            consumed=128000),
             integrity()),
        ]
        for name, issued, obs, cov, integ in shapes:
            s = stage_result(issued, issued, obs, cov)
            ok, _ = oracles.check_overload_stage(name, s, integ)
            self.assertFalse(ok, f"{name} stage must fail with zero named counter")

    def test_gap_exceeding_all_loss_buckets_fails(self):
        # A gap no loss counter can cover is unexplained loss, not a
        # proved partial: issued 38000, observed 3, trivial counters.
        cov = coverage(3, prog_miss=3, accepted=24, consumed=24)
        s = stage_result(38000, 38000, 3, cov)
        ok, detail = oracles.check_overload_stage("ring", s, integrity())
        self.assertFalse(ok)
        self.assertEqual(detail["gap"], 37997)


class E07PositiveTests(unittest.TestCase):
    def test_ring_overload_with_reconciled_gap_passes(self):
        # E03-shape evidence: exact arrival equation, closed transport,
        # gap covered by the named ring counter.
        cov = coverage(14728, accepted=120000, consumed=117827,
                       ring_drops=2173, count_loss=12809)
        s = stage_result(15000, 15000, 14728, cov)
        ok, detail = oracles.check_overload_stage(
            "ring", s, integrity(ring=2173, unmatched_e=1, unmatched_r=2))
        self.assertTrue(ok, detail)
        self.assertEqual(detail["gap"], 272)

    def test_map_overload_with_reconciled_gap_passes(self):
        # Parallel-flood shape: hook-miss pressure lands in the
        # state-insert bucket (product taxonomy); arrival exact.
        cov = coverage(19992, prog_miss=50, accepted=159950, consumed=159950)
        s = stage_result(20000, 20000, 19992, cov)
        ok, detail = oracles.check_overload_stage(
            "map", s, integrity(state=50))
        self.assertTrue(ok, detail)

    def test_user_overload_with_reconciled_gap_passes(self):
        cov = coverage(15900, accepted=128000, consumed=128000)
        s = stage_result(16000, 16000, 15900, cov)
        ok, detail = oracles.check_overload_stage(
            "user", s, integrity(user=100))
        self.assertTrue(ok, detail)


class E05CounterexampleTests(unittest.TestCase):
    def test_single_observation_active_case_fails(self):
        # Reviewers' mutation: both active cases changed to one
        # observation — the p2b inequality still returned PASS.
        case = stop_case("active-burst", 1655, 1)
        snapshot = {"pre_sigint": 1497, "post_before_exit": 110}
        product = {"coverage": coverage(1), "integrity": integrity()}
        ok, detail = oracles.check_stop_case(
            "active-burst", 0, case, snapshot, product)
        self.assertFalse(ok, detail)

    def test_product_exceeding_snapshot_plus_tail_fails(self):
        # More observations than pre-SIGINT completions plus the bounded
        # drained tail cannot be a closed equation.
        case = stop_case("active-burst", 1655, 1650)
        snapshot = {"pre_sigint": 1497, "post_before_exit": 110}
        product = {"coverage": coverage(1600), "integrity": integrity()}
        ok, _ = oracles.check_stop_case(
            "active-burst", 0, case, snapshot, product)
        self.assertFalse(ok)


class E05PositiveTests(unittest.TestCase):
    def test_active_burst_exact_snapshot_equation_passes(self):
        # Preserved r4 shape: product == pre-SIGINT + drained tail (4),
        # tail within the post-SIGINT completions before CLI exit, zero
        # transport loss in the case report.
        case = stop_case("active-burst", 1655, 1501)
        snapshot = {"pre_sigint": 1497, "post_before_exit": 110}
        cov = coverage(1501, accepted=3034, consumed=3034)
        product = {"coverage": cov, "integrity": integrity()}
        ok, detail = oracles.check_stop_case(
            "active-burst", 0, case, snapshot, product)
        self.assertTrue(ok, detail)
        self.assertEqual(detail["tail"], 4)

    def test_before_go_exact_zero_passes(self):
        case = stop_case("before-GO", 0, 0)
        ok, _ = oracles.check_stop_case("before-GO", 0, case, None, None)
        self.assertTrue(ok)

    def test_closing_drain_exact_completion_passes(self):
        case = stop_case("closing-drain", 1000, 1000)
        ok, _ = oracles.check_stop_case("closing-drain", 0, case, None, None)
        self.assertTrue(ok)


class TotalsCapOracleTests(unittest.TestCase):
    def test_ring_drop_fails_totals_checks(self):
        # C4's receipt-level half: the checker must report the failed
        # gate (the verifier half lives in test_inputs.py).
        cov = coverage(1000, ring_drops=1, accepted=8000, consumed=7999)
        r = stage_result(1000, 1000, 1000, cov)
        r["distinct_request_ids"] = 1000
        r["output_bytes"] = 100
        r["attach_ready_latency_s"] = 0.1
        checks, _ = oracles.check_totals(r, "E01a")
        self.assertFalse(checks["zero_ring_drops"])
        self.assertFalse(checks["agg_consumed_eq_accepted"])

    def test_exact_totals_pass(self):
        cov = coverage(1000, accepted=8000, consumed=8000)
        r = stage_result(1000, 1000, 1000, cov)
        r["distinct_request_ids"] = 1000
        r["output_bytes"] = 100
        r["attach_ready_latency_s"] = 0.1
        checks, bundle = oracles.check_totals(r, "E01a")
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(bundle["observation"]["expected"], 1000)

    def test_cap_boundary_passes(self):
        cov = coverage(100005, accepted=800040, consumed=800040,
                       truncated=5)
        r = stage_result(100005, 100005, 100000, cov)
        r["distinct_request_ids"] = 100000
        r["output_bytes"] = 10**6
        r["verdict"] = {"status": "partial",
                        "missing": ["attribution", "completion"]}
        checks, bundle = oracles.check_cap(r)
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(bundle["observation"]["actual"], 100005)

    def test_failed_checks_fail_verify_end_to_end(self):
        # Checker + verifier together: a failed zero-loss gate cannot
        # ride an otherwise clean receipt to PASS.
        cov = coverage(1000, ring_drops=1, accepted=8000, consumed=7999)
        r = stage_result(1000, 1000, 1000, cov)
        r["distinct_request_ids"] = 1000
        r["output_bytes"] = 100
        r["attach_ready_latency_s"] = 0.1
        checks, bundle = oracles.check_totals(r, "E01a")
        rec = {
            "process": {"exit": 0, "timed_out": False, "reaped": True},
            "cleanup": {"remaining_owned": {}, "preexisting_unchanged": True},
            "custody": {"hashes_unchanged": True},
            "observation": bundle["observation"],
            "checks": checks,
            "oracle_failed": [k for k, v in checks.items() if not v],
        }
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
