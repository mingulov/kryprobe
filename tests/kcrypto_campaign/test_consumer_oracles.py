#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the P8/T13 real-consumer oracle predicates.

Standard library only; no guests, no privilege. Each oracle is a
pure predicate over archived cell facts; every test pins a valid
control and its causal mutations. Run from the product worktree
root::

    python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_consumer_oracles.py'
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_campaign import oracles  # noqa: E402


def det_leg(ops=4, skcipher=8, alloc=4, destroy=4):
    return {
        "ledger_ops": ops,
        "ledger_rc": 0,
        "attach_markers": 10,
        "product": {"skcipher": skcipher, "alloc": alloc, "destroy": destroy},
    }


class R01DetTests(unittest.TestCase):
    def test_identical_legs_pass(self):
        checks, detail = oracles.check_r01_det(det_leg(), det_leg())
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(detail["ledger_ops"], 4)

    def test_divergent_counts_fail(self):
        checks, _detail = oracles.check_r01_det(det_leg(), det_leg(skcipher=9))
        self.assertFalse(checks["deterministic_counts"])

    def test_failed_ledger_validation_fails(self):
        bad = det_leg()
        bad["ledger_rc"] = 1
        checks, _detail = oracles.check_r01_det(det_leg(), bad)
        self.assertFalse(checks["ledgers_valid"])

    def test_missing_attach_markers_fail(self):
        bad = det_leg()
        bad["attach_markers"] = 0
        checks, _detail = oracles.check_r01_det(det_leg(), bad)
        self.assertFalse(checks["attach_proved"])


def floor_workload(hash_issued=20, hash_done=20, skc_issued=10, skc_done=10):
    return {"hash_issued": hash_issued, "hash_done": hash_done,
            "skc_issued": skc_issued, "skc_done": skc_done}


def floor_kernel(ahash=20, shash=20, finup=0, enc=20, dec=20):
    return {"ahash_digest": ahash, "shash_digest": shash, "shash_finup": finup,
            "skcipher_encrypt": enc, "skcipher_decrypt": dec}


def floor_product(ahash=20, shash=20, finup=0, enc=20, dec=20, drops="0"):
    return {"ahash_digest": ahash, "shash_digest": shash, "shash_finup": finup,
            "skcipher_encrypt": enc, "skcipher_decrypt": dec,
            "ring_drops": drops}


def floor_refusal(exit_code=4, stderr="live session unusable: fsession attach failed"):
    # The oracle gates on the STABLE contract (exit 4 = Unusable);
    # stderr is archived evidence, quoted in the handoff, never
    # scripted (docs/json.md: stderr is human-only).
    return {"exit": exit_code, "stderr": stderr}


class R01FloorTests(unittest.TestCase):
    def test_aggregate_plus_refusal_passes(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(), floor_product(), floor_refusal())
        self.assertTrue(all(checks.values()), checks)

    def test_unproved_workload_fails(self):
        bad = floor_workload(hash_done=19)
        checks, _detail = oracles.check_r01_floor(
            bad, floor_kernel(), floor_product(), floor_refusal())
        self.assertFalse(checks["workload_proved"])

    def test_product_kernel_divergence_fails(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(), floor_product(shash=19), floor_refusal())
        self.assertFalse(checks["hash_kernel_equal"])

    def test_skcipher_divergence_fails(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(), floor_product(dec=19), floor_refusal())
        self.assertFalse(checks["skcipher_kernel_equal"])

    def test_missing_nesting_fails_route(self):
        # Kernel shows no cryptd nesting (1x issued): equality
        # still holds (product matches kernel) but the documented
        # 6.12 route does not.
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(enc=10, dec=10),
            floor_product(enc=10, dec=10), floor_refusal())
        self.assertTrue(checks["skcipher_kernel_equal"])
        self.assertFalse(checks["skcipher_route_documented"])

    def test_undocumented_route_fails(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=40),
            floor_product(shash=40), floor_refusal())
        self.assertTrue(checks["hash_kernel_equal"])
        self.assertFalse(checks["hash_route_documented"])

    def test_finup_route_passes(self):
        # Scatterlist-shaped nesting: the same 20 digests nest
        # one finup each instead of one digest (R01-floor-612
        # re-run). Kernel and product agree exactly on the taken
        # arm; the digest arm reads a recorded zero.
        checks, detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=0, finup=20),
            floor_product(shash=0, finup=20), floor_refusal())
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(detail["nested_route"], "finup-1x")

    def test_finup_double_route_passes(self):
        # Split scatterlists nest two finups per digest (7.0.14
        # R04-foreign shape, 12/6): admitted with exact
        # kernel==product equality on the taken arm.
        checks, detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=0, finup=40),
            floor_product(shash=0, finup=40), floor_refusal())
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(detail["nested_route"], "finup-2x")

    def test_mixed_nesting_fails_route(self):
        # Digest AND finup nonzero: no admitted arm (the re-wave
        # never mixes arms within one burst); equality holds but
        # the route is undocumented.
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=10, finup=10),
            floor_product(shash=10, finup=10), floor_refusal())
        self.assertTrue(checks["hash_kernel_equal"])
        self.assertFalse(checks["hash_route_documented"])

    def test_absent_nesting_fails_nonempty(self):
        # Neither nested function fired: the digests are
        # unaccounted below the outer call.
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=0, finup=0),
            floor_product(shash=0, finup=0), floor_refusal())
        self.assertFalse(checks["kernel_nonempty"])
        self.assertFalse(checks["hash_route_documented"])

    def test_finup_divergence_fails(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=0, finup=20),
            floor_product(shash=0, finup=19), floor_refusal())
        self.assertFalse(checks["hash_kernel_equal"])

    def test_dropped_product_fails(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(), floor_product(drops="1"), floor_refusal())
        self.assertFalse(checks["product_lossless"])

    def test_zero_exit_refusal_fails(self):
        bad = floor_refusal(exit_code=0, stderr="ok")
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(), floor_product(), bad)
        self.assertFalse(checks["refusal_exit_unusable"])

    def test_internal_defect_exit_fails(self):
        bad = floor_refusal(exit_code=1, stderr="live session internal error: x")
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(), floor_product(), bad)
        self.assertFalse(checks["refusal_exit_unusable"])


def r02_workload(written=64 * 1024, read=64 * 1024, match=True):
    return {"bytes_written": written, "bytes_read": read, "checksums_match": match}


def r02_kernel(enc=128, dec=128):
    return {"skcipher_encrypt": enc, "skcipher_decrypt": dec}


def r02_product(enc=128, dec=128, enc_bytes=64 * 1024, dec_bytes=64 * 1024):
    return {
        "skcipher_encrypt": enc,
        "skcipher_decrypt": dec,
        "enc_bytes": enc_bytes,
        "dec_bytes": dec_bytes,
        "ring_drops": "0",
    }


def quiet(counts=None):
    return {"product_rows": 0, "kernel_hits": 0, "rows": counts or []}


class R02Tests(unittest.TestCase):
    def test_exact_match_passes(self):
        checks, detail = oracles.check_r02(
            r02_workload(), r02_kernel(), r02_product(), quiet(), quiet()
        )
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(detail["chunk_bytes"], 512)

    def test_checksum_mismatch_fails(self):
        checks, _d = oracles.check_r02(
            r02_workload(match=False), r02_kernel(), r02_product(), quiet(), quiet()
        )
        self.assertFalse(checks["workload_integral"])

    def test_product_kernel_divergence_fails(self):
        checks, _d = oracles.check_r02(
            r02_workload(), r02_kernel(), r02_product(enc=127), quiet(), quiet()
        )
        self.assertFalse(checks["calls_equal_kernel"])

    def test_unreconciled_bytes_fail(self):
        bad = r02_product(dec_bytes=64 * 1024 - 512)
        checks, _d = oracles.check_r02(r02_workload(), r02_kernel(), bad, quiet(), quiet())
        self.assertFalse(checks["bytes_reconcile"])

    def test_non_chunked_sizes_fail(self):
        bad = r02_product(enc_bytes=65537, dec_bytes=65535)
        checks, _d = oracles.check_r02(r02_workload(), r02_kernel(), bad, quiet(), quiet())
        self.assertFalse(checks["chunking_explained"])

    def test_split_direction_quotients_fail(self):
        bad = r02_product(enc_bytes=64 * 1024, dec_bytes=32 * 1024)
        other = r02_workload(written=64 * 1024, read=32 * 1024)
        kernel = r02_kernel(enc=128, dec=128)
        bad = r02_product(enc=128, dec=128, enc_bytes=64 * 1024, dec_bytes=32 * 1024)
        checks, _d = oracles.check_r02(other, kernel, bad, quiet(), quiet())
        self.assertTrue(checks["bytes_reconcile"])
        self.assertFalse(checks["chunking_explained"])

    def test_noisy_quiet_window_fails(self):
        noisy = quiet()
        noisy["product_rows"] = 2
        checks, _d = oracles.check_r02(
            r02_workload(), r02_kernel(), r02_product(), noisy, quiet()
        )
        self.assertFalse(checks["quiet_bounded"])

    def test_zero_kernel_traffic_fails(self):
        checks, _d = oracles.check_r02(
            r02_workload(), r02_kernel(0, 0), r02_product(0, 0, 0, 0), quiet(), quiet()
        )
        self.assertFalse(checks["kernel_traffic_proved"])


def r03_ledgers(sent=1000, received=1000):
    return {"sent": sent, "received": received}


def r03_kernel(enc=2000, dec=2000):
    return {"aead_encrypt": enc, "aead_decrypt": dec}


def r03_product(enc=2000, dec=2000, dec_errors=0, errnos=None,
               kenc=None, kdec=None):
    return {
        "aead_encrypt": enc,
        "aead_decrypt": dec,
        "aead_decrypt_errors": dec_errors,
        "kernel_encrypt": enc if kenc is None else kenc,
        "kernel_decrypt": dec if kdec is None else kdec,
        "error_errnos": errnos or [],
        "ring_drops": "0",
    }


def r03_authfail_ok():
    # Nested failure: both echainiv levels error (200 errors for
    # 100 packets), zero ok-decrypts, encrypts kernel-equal.
    return r03_product(enc=200, dec=0, dec_errors=200, errnos=[-74],
                       kenc=200, kdec=200)


class R03Tests(unittest.TestCase):
    def test_exact_match_passes(self):
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 0},
            r03_authfail_ok(),
            quiet(), quiet(),
        )
        self.assertTrue(all(checks.values()), checks)

    def test_lost_packets_fail(self):
        checks, _d = oracles.check_r03(
            r03_ledgers(received=999), r03_ledgers(), r03_kernel(dec=1999),
            r03_product(dec=1999),
            {"sent": 100, "received": 0},
            r03_authfail_ok(),
            quiet(), quiet(),
        )
        self.assertFalse(checks["ledgers_lossless"])

    def test_packet_call_conflation_fails(self):
        # Product decrypts must equal the KERNEL reference, not the
        # packet ledger: a kernel retry/batch the ledger never saw
        # must fail, never be absorbed.
        prod = r03_product(dec=2001)
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), prod,
            {"sent": 100, "received": 0},
            r03_authfail_ok(),
            quiet(), quiet(),
        )
        self.assertFalse(checks["calls_equal_kernel"])

    def test_authfail_success_bytes_fail(self):
        bad = r03_product(enc=200, dec=1, dec_errors=199, errnos=[-74],
                          kenc=200, kdec=200)
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 1}, bad, quiet(), quiet(),
        )
        self.assertFalse(checks["authfail_exact"])
        self.assertFalse(checks["authfail_counts_equal"])

    def test_authfail_partial_errors_fail(self):
        # One nesting level unobserved: errors below kernel decrypts.
        bad = r03_product(enc=200, dec=0, dec_errors=100, errnos=[-74],
                          kenc=200, kdec=200)
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 0}, bad, quiet(), quiet(),
        )
        self.assertFalse(checks["authfail_counts_equal"])

    def test_authfail_ok_decrypts_fail(self):
        # Phantom ok-decrypts alongside kernel-equal errors.
        bad = r03_product(enc=200, dec=50, dec_errors=200, errnos=[-74],
                          kenc=200, kdec=200)
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 0}, bad, quiet(), quiet(),
        )
        self.assertFalse(checks["authfail_counts_equal"])

    def test_swallowed_errno_fails(self):
        bad = r03_product(enc=200, dec=0, dec_errors=200, errnos=[],
                          kenc=200, kdec=200)
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 0}, bad, quiet(), quiet(),
        )
        self.assertFalse(checks["authfail_errno_native"])


def deny_control(issued=10, done=10, observed=None, drops="0"):
    return {"hash_issued": issued, "hash_done": done,
            "observed": observed if observed is not None else {"ahash_digest": 10},
            "ring_drops": drops}


def frow(tgid, probe, calls):
    return [{"tgid": tgid, "probe": probe, "calls": calls}]


class R04Tests(unittest.TestCase):
    def test_deny_plus_control_passes(self):
        checks, _d = oracles.check_r04_deny(
            {"exit": 4, "stderr": "live session unusable: missing CAP_BPF"},
            deny_control(),
            {"ahash_digest": 10},
        )
        self.assertTrue(all(checks.values()), checks)

    def test_zero_exit_deny_fails(self):
        checks, _d = oracles.check_r04_deny(
            {"exit": 0, "stderr": ""},
            deny_control(),
            {"ahash_digest": 10},
        )
        self.assertFalse(checks["refusal_exit_unusable"])

    def test_failed_control_workload_fails(self):
        checks, _d = oracles.check_r04_deny(
            {"exit": 4, "stderr": "live session unusable: missing CAP_BPF"},
            deny_control(done=9),
            {"ahash_digest": 10},
        )
        self.assertFalse(checks["control_workload_proved"])

    def test_control_kernel_divergence_fails(self):
        bad = deny_control(observed={"ahash_digest": 9})
        checks, _d = oracles.check_r04_deny(
            {"exit": 4, "stderr": "live session unusable: missing CAP_BPF"},
            bad,
            {"ahash_digest": 10},
        )
        self.assertFalse(checks["control_kernel_equal"])

    def test_unused_function_reads_zero_both_sides(self):
        # A genuinely unused route function (kernel 0, product 0)
        # is an explicit recorded zero, not a skip: equality holds
        # while traffic elsewhere proves the window ran.
        control = deny_control(observed={"ahash_digest": 10, "shash_digest": 0})
        checks, _d = oracles.check_r04_deny(
            {"exit": 4, "stderr": "live session unusable: x"},
            control,
            {"ahash_digest": 10, "shash_digest": 0},
        )
        self.assertTrue(all(checks.values()), checks)

    def test_empty_kernel_window_fails(self):
        control = deny_control(observed={"ahash_digest": 0})
        checks, _d = oracles.check_r04_deny(
            {"exit": 4, "stderr": "live session unusable: x"},
            control,
            {"ahash_digest": 0},
        )
        self.assertFalse(checks["control_nonempty"])

    def test_foreign_correspondence_passes(self):
        # Real 7.0.14 shape (R04-foreign-7014 seal): owned takes
        # digest-nesting (20 outer + 20 shash + 1 bind-alloc) while
        # foreign takes finup-nesting (6 outer + 12 finup + 1
        # bind-alloc). Outer ratio is exactly 20:6, allocs are
        # exactly 1:1, and who covers every agg call (60/60).
        rows = (frow(101, "ahash", 20) + frow(101, "shash", 20)
                + frow(101, "alloc", 1) + frow(202, "ahash", 6)
                + frow(202, "finup", 12) + frow(202, "alloc", 1))
        checks, detail = oracles.check_r04_foreign(
            [101], [202], 20, 6, rows, 60)
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(detail["owned_outer"], 20)
        self.assertEqual(detail["foreign_outer"], 6)
        self.assertEqual(detail["who_total"], 60)

    def test_foreign_totals_ratio_is_not_the_proof(self):
        # Regression: summing every who row per set (41:19 here)
        # can never equal the 20:6 issued ratio once bind-allocs
        # are attributed, and digest-only coverage (58) can never
        # cover alloc-bearing who totals (60). The proof is the
        # outer-only ratio plus all-families coverage.
        rows = (frow(101, "ahash", 20) + frow(101, "shash", 20)
                + frow(101, "alloc", 1) + frow(202, "ahash", 6)
                + frow(202, "finup", 12) + frow(202, "alloc", 1))
        owned_total = sum(r["calls"] for r in rows if r["tgid"] == 101)
        foreign_total = sum(r["calls"] for r in rows if r["tgid"] == 202)
        self.assertEqual((owned_total, foreign_total), (41, 19))
        self.assertNotEqual(owned_total * 6, foreign_total * 20)
        checks, _d = oracles.check_r04_foreign(
            [101], [202], 20, 6, rows, 58)
        self.assertFalse(checks["coverage_exact"])

    def test_foreign_absorbed_fails(self):
        # Foreign rows claimed as owned: the ratio breaks (26:0
        # over disjoint sets is unprovable) and the empty foreign
        # set fails the disjointness gate.
        rows = ([{"tgid": 101, "probe": "ahash", "calls": 1}] * 20
                + [{"tgid": 202, "probe": "ahash", "calls": 1}] * 6)
        checks, _d = oracles.check_r04_foreign([101, 202], [], 26, 0, rows, 26)
        self.assertFalse(checks["pid_sets_disjoint"])

    def test_skewed_outer_ratio_fails(self):
        # 19:7 outer is not 20:6 — one owned outer observation
        # leaked to the foreign set; the correspondence is broken
        # even though the all-in totals still cover.
        rows = (frow(101, "ahash", 19) + frow(101, "alloc", 1)
                + frow(202, "ahash", 7) + frow(202, "alloc", 1))
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 28)
        self.assertFalse(checks["ratio_exact"])

    def test_foreign_alloc_misattributed_fails(self):
        # The owned bind-alloc attributed to the foreign PID keeps
        # the outer ratio and the coverage equation green while
        # the per-burst alloc shape (1:1) breaks: alloc_exact
        # catches the misattribution the totals cannot see.
        rows = (frow(101, "ahash", 20) + frow(202, "ahash", 6)
                + frow(202, "alloc", 2))
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 28)
        self.assertTrue(checks["ratio_exact"])
        self.assertTrue(checks["coverage_exact"])
        self.assertFalse(checks["alloc_exact"])

    def test_unclassified_probe_fails(self):
        # A who row the parser could not map to a scenario probe
        # (or a probe outside the hash-only traffic contract)
        # fails closed instead of joining a silent total.
        rows = (frow(101, "ahash", 20) + frow(101, "alloc", 1)
                + frow(202, "ahash", 6) + frow(202, "alloc", 1)
                + [{"tgid": 101, "probe": None, "calls": 2}])
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 30)
        self.assertFalse(checks["probes_classified"])

    def test_uncovered_agg_fails(self):
        # Who attribution (26 outer + 2 alloc) misses 32 nested
        # agg observations: the coverage equation fails even
        # though the outer ratio holds.
        rows = (frow(101, "ahash", 20) + frow(101, "alloc", 1)
                + frow(202, "ahash", 6) + frow(202, "alloc", 1))
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 60)
        self.assertFalse(checks["coverage_exact"])

    def test_unattributed_rows_fail(self):
        rows = (frow(101, "ahash", 20) + frow(101, "alloc", 1)
                + frow(202, "ahash", 6) + frow(202, "alloc", 1)
                + frow(999, "ahash", 2))
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 30)
        self.assertFalse(checks["no_unattributed_rows"])

    def test_missing_foreign_decoy_fails(self):
        rows = frow(101, "ahash", 20) + frow(101, "alloc", 1)
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 21)
        self.assertFalse(checks["foreign_present"])

    def test_vacuous_zero_outer_fails(self):
        # 0:0 outer satisfies the ratio equation trivially; the
        # foreign-presence gate keeps the vacuous pass out.
        rows = frow(101, "alloc", 1) + frow(202, "alloc", 1)
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 2)
        self.assertFalse(checks["foreign_present"])


def agg_obs(family="skcipher", op="encrypt", result="ok", calls=20,
            errors=0, name="crypto_skcipher_encrypt", extra=None):
    payload = {
        "row": "agg", "family": family, "op": op, "result": result,
        "algorithm": "cbc(aes)", "driver": "cbc-aes-aesni",
        "context": "process", "bytes": 640,
        "counts": {"calls": calls, "errors": errors, "ok": calls - errors, "queued": 0},
        "status_canonical": True,
        "window": {"first_ns": 1, "last_ns": 2},
    }
    if extra:
        payload.update(extra)
    return {"id": "observation:7", "backend": "kcrypto",
            "native_name": name, "backend_payload": payload}


def who_obs(tgid=101, calls=20, first_errno=None):
    payload = {"row": "who", "key_hash": 9, "tgid": tgid, "tid": tgid,
               "comm": "kcrypto_gen", "uid": 0, "calls": calls,
               "capture_profile": "api-returns"}
    if first_errno is not None:
        payload["first_errno"] = first_errno
    return {"id": "observation:8", "backend": "kcrypto",
            "native_name": None, "backend_payload": payload}


def report_doc(*observations, ring_drops="0", ktot_gap="0"):
    return {
        "observations": list(observations),
        "coverage": {
            "aggregate_counts": {"status": "s", "counters": [
                {"name": "ktot_gap", "value": ktot_gap}]},
            "detailed_events": {"status": "s", "counters": [
                {"name": "ring_drops", "value": ring_drops}]},
            "attachment": {"status": "s", "counters": [
                {"name": "probes_attached", "value": "9"},
                {"name": "probes_expected", "value": "9"}]},
            "completion": {"status": "s", "counters": []},
        },
        "integrity": {"ring_reservation_failures": "0",
                      "user_queue_drops": "0",
                      "state_insert_failures": "0",
                      "budget_omissions": "0"},
        "verdict": {"status": "complete", "missing": []},
    }


class ReportParserTests(unittest.TestCase):
    def test_parse_counts_rows_and_who(self):
        doc = report_doc(agg_obs(), who_obs())
        parsed = oracles.parse_api_returns_report(doc)
        key = ("skcipher", "encrypt", "ok", "cbc(aes)", "cbc-aes-aesni", "process")
        self.assertEqual(parsed["agg"][key]["calls"], 20)
        self.assertEqual(parsed["who"], [{"tgid": 101, "tid": 101,
                                          "comm": "kcrypto_gen", "uid": 0,
                                          "calls": 20, "first_errno": None,
                                          "probe": None}])
        self.assertEqual(parsed["loss"]["ring_drops"], "0")
        self.assertEqual(parsed["loss"]["ktot_gap"], "0")
        self.assertEqual(parsed["attach"]["probes_attached"], "9")
        self.assertEqual(parsed["attach"]["probes_expected"], "9")

    def test_parse_collapses_exact_duplicates(self):
        first, second = agg_obs(), agg_obs()
        second["id"] = "observation:26"
        parsed = oracles.parse_api_returns_report(report_doc(first, second))
        key = ("skcipher", "encrypt", "ok", "cbc(aes)", "cbc-aes-aesni", "process")
        self.assertEqual(parsed["agg"][key]["calls"], 20)
        self.assertEqual(parsed["duplicates_collapsed"], 1)

    def test_parse_keeps_algorithm_split_rows(self):
        # Same (family, op, result), different algorithms: three
        # alloc rows coexist (the 6.12 floor shape).
        rows = [agg_obs(family="any", op="alloc", calls=1, name="crypto_alloc_tfm_node",
                         extra={"algorithm": algo, "driver": "", "context": "process"})
                for algo in ("cbc(aes)", "cryptd(__cbc-aes-aesni)", "sha256")]
        parsed = oracles.parse_api_returns_report(report_doc(*rows))
        self.assertEqual(len(parsed["agg"]), 3)
        self.assertEqual(parsed["duplicates_collapsed"], 0)

    def test_parse_rejects_conflicting_agg_rows(self):
        with self.assertRaisesRegex(oracles.OracleError, "conflicting"):
            oracles.parse_api_returns_report(
                report_doc(agg_obs(calls=20), agg_obs(calls=21)))

    def test_parse_rejects_unknown_row(self):
        bad = agg_obs()
        bad["backend_payload"]["row"] = "mystery"
        with self.assertRaisesRegex(oracles.OracleError, "unknown row"):
            oracles.parse_api_returns_report(report_doc(bad))

    def test_parse_rejects_missing_top_keys(self):
        doc = report_doc(agg_obs())
        del doc["integrity"]
        with self.assertRaisesRegex(oracles.OracleError, "missing keys"):
            oracles.parse_api_returns_report(doc)

    def test_parse_rejects_who_without_tgid(self):
        bad = who_obs()
        del bad["backend_payload"]["tgid"]
        with self.assertRaisesRegex(oracles.OracleError, "tgid"):
            oracles.parse_api_returns_report(report_doc(bad))

    def test_parse_labels_who_probe_from_stack(self):
        # The first kcrypto frame names the probe family; rows
        # without a stack (or without a kcrypto frame) parse with
        # probe None and let the oracle fail closed, never the
        # parser.
        ahash = who_obs(tgid=101, calls=20)
        ahash["backend_payload"]["stack"] = {"id": 693, "frames": [
            {"sym": "bpf_prog_927a780be69a1c52_kcrypto_ahash"},
            {"sym": "bpf_trampoline_6442556524"},
            {"sym": "hash_sendmsg"},
        ]}
        alloc = who_obs(tgid=101, calls=1)
        alloc["backend_payload"]["stack"] = {"id": 725, "frames": [
            {"sym": "bpf_prog_3a94273105c32b1b_kcrypto_alloc"},
            {"sym": "crypto_alloc_ahash"},
        ]}
        parsed = oracles.parse_api_returns_report(
            report_doc(ahash, alloc, who_obs(tgid=202, calls=6)))
        probes = [(row["tgid"], row["probe"], row["calls"]) for row in parsed["who"]]
        self.assertEqual(probes, [(101, "ahash", 20), (101, "alloc", 1),
                                  (202, None, 6)])


if __name__ == "__main__":
    unittest.main()
