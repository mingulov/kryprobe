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


def floor_kernel(ahash=20, shash=20, enc=10, dec=10):
    return {"ahash_digest": ahash, "shash_digest": shash,
            "skcipher_encrypt": enc, "skcipher_decrypt": dec}


def floor_product(ahash=20, shash=20, enc=10, dec=10, drops="0"):
    return {"ahash_digest": ahash, "shash_digest": shash,
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
            floor_workload(), floor_kernel(), floor_product(dec=9), floor_refusal())
        self.assertFalse(checks["skcipher_kernel_equal"])

    def test_undocumented_route_fails(self):
        checks, _detail = oracles.check_r01_floor(
            floor_workload(), floor_kernel(shash=40),
            floor_product(shash=40), floor_refusal())
        self.assertTrue(checks["hash_kernel_equal"])
        self.assertFalse(checks["hash_route_documented"])

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


def r03_product(enc=2000, dec=2000, dec_errors=0, errnos=None):
    return {
        "aead_encrypt": enc,
        "aead_decrypt": dec,
        "aead_decrypt_errors": dec_errors,
        "error_errnos": errnos or [],
        "ring_drops": "0",
    }


class R03Tests(unittest.TestCase):
    def test_exact_match_passes(self):
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 0},
            r03_product(enc=100, dec=100, dec_errors=100, errnos=[-74]),
            quiet(), quiet(),
        )
        self.assertTrue(all(checks.values()), checks)

    def test_lost_packets_fail(self):
        checks, _d = oracles.check_r03(
            r03_ledgers(received=999), r03_ledgers(), r03_kernel(dec=1999),
            r03_product(dec=1999),
            {"sent": 100, "received": 0},
            r03_product(enc=100, dec=100, dec_errors=100, errnos=[-74]),
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
            r03_product(enc=100, dec=100, dec_errors=100, errnos=[-74]),
            quiet(), quiet(),
        )
        self.assertFalse(checks["calls_equal_kernel"])

    def test_authfail_success_bytes_fail(self):
        bad = r03_product(enc=100, dec=100, dec_errors=99, errnos=[-74])
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 1}, bad, quiet(), quiet(),
        )
        self.assertFalse(checks["authfail_exact"])

    def test_swallowed_errno_fails(self):
        bad = r03_product(enc=100, dec=100, dec_errors=100, errnos=[])
        checks, _d = oracles.check_r03(
            r03_ledgers(), r03_ledgers(), r03_kernel(), r03_product(),
            {"sent": 100, "received": 0}, bad, quiet(), quiet(),
        )
        self.assertFalse(checks["authfail_errno_native"])


def deny_control(issued=10, done=10, observed=None, drops="0"):
    return {"hash_issued": issued, "hash_done": done,
            "observed": observed if observed is not None else {"ahash_digest": 10},
            "ring_drops": drops}


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
        # Route-shaped multiplier (2 observations per digest: ahash
        # + nested shash): the proof is the 20:6 ratio plus exact
        # agg coverage, never the absolute 40/12.
        rows = [{"tgid": 101, "calls": 20}] * 2 + [{"tgid": 202, "calls": 6}] * 2
        checks, detail = oracles.check_r04_foreign(
            [101], [202], 20, 6, rows, 52)
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(detail["owned_matched"], 40)
        self.assertEqual(detail["foreign_matched"], 12)

    def test_foreign_absorbed_fails(self):
        # Foreign rows claimed as owned: the ratio breaks (26:0
        # over disjoint sets is unprovable) and the empty foreign
        # set fails the disjointness gate.
        rows = [{"tgid": 101, "calls": 1}] * 20 + [{"tgid": 202, "calls": 1}] * 6
        checks, _d = oracles.check_r04_foreign([101, 202], [], 26, 0, rows, 26)
        self.assertFalse(checks["pid_sets_disjoint"])

    def test_skewed_ratio_fails(self):
        # 39:13 is not 20:6 — one owned observation leaked to the
        # foreign set (or vice versa); the correspondence is broken.
        rows = [{"tgid": 101, "calls": 39}, {"tgid": 202, "calls": 13}]
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 52)
        self.assertFalse(checks["ratio_exact"])

    def test_uncovered_agg_fails(self):
        # Who attribution (40+12) misses 2 agg observations: the
        # coverage equation fails even though the ratio holds.
        rows = [{"tgid": 101, "calls": 20}] * 2 + [{"tgid": 202, "calls": 6}] * 2
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 54)
        self.assertFalse(checks["coverage_exact"])

    def test_unattributed_rows_fail(self):
        rows = ([{"tgid": 101, "calls": 20}] * 2 + [{"tgid": 202, "calls": 6}] * 2
                + [{"tgid": 999, "calls": 2}])
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 54)
        self.assertFalse(checks["no_unattributed_rows"])

    def test_missing_foreign_decoy_fails(self):
        rows = [{"tgid": 101, "calls": 20}] * 2
        checks, _d = oracles.check_r04_foreign([101], [202], 20, 6, rows, 40)
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
        self.assertEqual(
            parsed["agg"][("skcipher", "encrypt", "ok")]["calls"], 20)
        self.assertEqual(parsed["who"], [{"tgid": 101, "tid": 101,
                                          "comm": "kcrypto_gen", "uid": 0,
                                          "calls": 20, "first_errno": None}])
        self.assertEqual(parsed["loss"]["ring_drops"], "0")
        self.assertEqual(parsed["loss"]["ktot_gap"], "0")
        self.assertEqual(parsed["attach"]["probes_attached"], "9")
        self.assertEqual(parsed["attach"]["probes_expected"], "9")

    def test_parse_collapses_exact_duplicates(self):
        first, second = agg_obs(), agg_obs()
        second["id"] = "observation:26"
        parsed = oracles.parse_api_returns_report(report_doc(first, second))
        self.assertEqual(
            parsed["agg"][("skcipher", "encrypt", "ok")]["calls"], 20)
        self.assertEqual(parsed["duplicates_collapsed"], 1)

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


if __name__ == "__main__":
    unittest.main()
