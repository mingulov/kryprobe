#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the M1 successor-epoch judge operands (Task07).

Freeze Amendment A12 (workspace ADR-0021): per observed leg,
observed + kernel misses = driver truth exact (zero tolerance),
per-program lane invariants (``ktot_gap == 0``), M-leg truth
checks. Oracle operands below are extracted verbatim from sealed
cells (never re-judged here — pure operand fixtures):

- K6-1/K6-2 (fixed bytes ``d151128``, evidence
  ``kcrypto-m1-06-ktot-fix/k6-reg/``): report counters, totals,
  stderr miss line, driver ``ops_total``; truth = 2*ops + 64.
- ``m1-P-4K-n_cgroup-mr`` leg00B (FORENSICS-2 51/51 sample):
  ledger ``system_total`` + stderr ``miss_delta`` = truth.
- ``m1-P-1M-n_cgroup-cr`` leg00B (old bytes, KTOT lag):
  ctx ``present_calls`` - report totals calls = 82 lag; the
  frozen parser refuses this report outright (no ``ktot_gap``
  counter) and the successor checker must judge it invalid.

Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf \
        -p 'test_successor.py'
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_perf import successorvalidity as succ  # noqa: E402


def write_tmp(content, suffix=""):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return Path(fh.name)


def report_doc(counters, detailed=()):
    return json.dumps({"coverage": {
        "aggregate_counts": {"counters": [
            {"name": n, "value": v} for n, v in counters]},
        "detailed_events": {"counters": [
            {"name": n, "value": v} for n, v in detailed]}}})


# Verbatim K6-1 aggregate_counts counters (fixed bytes d151128).
K6_1_COUNTERS = [
    ("uncovered:aggregate_snapshot_not_quiescent", "1"),
    ("kernel_misses", "22371"),
    ("snapshot_agg_calls", "8990845"),
    ("snapshot_totals_calls", "8990845"),
    ("ktot_gap", "0"),
    ("snapshot_gap_unreconciled", "0"),
    ("predrop_cfg_fail", "0"),
    ("predrop_fret_fail", "0"),
    ("predrop_arg_null", "0"),
    ("predrop_chase_fail", "0"),
    ("predrop_name_fail", "0"),
    ("predrop_destroy_skip", "64"),
    ("predrop_spare_6", "0"),
    ("predrop_spare_7", "0"),
]

K6_1_MISS_LINE = ('kryprobe: telemetry {"v":1,"misses":{"programs":9,'
                  '"miss_delta":22371,"run_delta":null}}\n')
M_LEG00B_MISS_LINE = ('kryprobe: telemetry {"v":1,"misses":{"programs":9,'
                      '"miss_delta":31340,"run_delta":null}}\n')

K6_1 = {"observed": 8990845, "truth": 9013216, "misses": 22371}
K6_2 = {"observed": 97977, "truth": 100442, "misses": 2465}


class KernelMissesCounterTests(unittest.TestCase):
    def test_parses_k6_kernel_misses(self):
        path = write_tmp(report_doc(K6_1_COUNTERS))
        self.assertEqual(succ.parse_kernel_misses_counter(path), 22371)

    def test_missing_counter_refuses_old_bytes(self):
        counters = [(n, v) for n, v in K6_1_COUNTERS
                    if n != "kernel_misses"]
        path = write_tmp(report_doc(counters))
        with self.assertRaises(ValueError):
            succ.parse_kernel_misses_counter(path)

    def test_duplicate_counter_refuses(self):
        path = write_tmp(report_doc(K6_1_COUNTERS
                                    + [("kernel_misses", "1")]))
        with self.assertRaises(ValueError):
            succ.parse_kernel_misses_counter(path)

    def test_mistyped_counter_refuses(self):
        for bad in ("-1", 1.5, True, "22x71"):
            counters = [(n, bad if n == "kernel_misses" else v)
                        for n, v in K6_1_COUNTERS]
            path = write_tmp(report_doc(counters))
            with self.assertRaises(ValueError, msg=f"value {bad!r}"):
                succ.parse_kernel_misses_counter(path)

    def test_snapshot_counters_k6(self):
        path = write_tmp(report_doc(K6_1_COUNTERS))
        snap = succ.parse_snapshot_counters(path)
        self.assertEqual(snap, {"snapshot_agg_calls": 8990845,
                                "snapshot_totals_calls": 8990845,
                                "ktot_gap": 0})

    def test_snapshot_missing_ktot_gap_refuses(self):
        counters = [(n, v) for n, v in K6_1_COUNTERS if n != "ktot_gap"]
        path = write_tmp(report_doc(counters))
        with self.assertRaises(ValueError):
            succ.parse_snapshot_counters(path)

    def test_report_has_counter(self):
        path = write_tmp(report_doc(K6_1_COUNTERS))
        self.assertTrue(succ.report_has_counter(
            path, "aggregate_counts", "kernel_misses"))
        self.assertFalse(succ.report_has_counter(
            path, "aggregate_counts", "no_such_counter"))
        self.assertFalse(succ.report_has_counter(
            path, "detailed_events", "kernel_misses"))

    def test_report_has_counter_propagates_malformed(self):
        # A decode failure must never read as "absent":
        # swallowing it let duplicate-member reports pass R.
        doc = ('{"coverage":{"aggregate_counts":{"counters":['
               '{"name":"kernel_misses","value":1,'
               '"value":0}]}}}')
        path = write_tmp(doc)
        with self.assertRaises(ValueError):
            succ.report_has_counter(
                path, "aggregate_counts", "kernel_misses")

    def test_load_strict_json(self):
        path = write_tmp('{"ops_total":100}')
        self.assertEqual(succ.load_strict_json(path),
                         {"ops_total": 100})
        for bad in ('{"a":1,"a":2}',
                     '{"v":NaN}',
                     '{"v":Infinity}',
                     '{"v":1,}'):
            with self.assertRaises(ValueError, msg=bad):
                succ.load_strict_json(write_tmp(bad))

    def test_nan_telemetry_refuses(self):
        path = write_tmp(K6_1_MISS_LINE
                         + 'kryprobe: telemetry {"v":1,"ctx":NaN}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_stderr_has_misses(self):
        self.assertTrue(succ.stderr_has_misses(
            write_tmp("noise\n" + K6_1_MISS_LINE)))
        self.assertTrue(succ.stderr_has_misses(
            write_tmp('kryprobe: telemetry {"v":1,"misses":\n')))
        self.assertTrue(succ.stderr_has_misses(
            write_tmp('kryprobe: telemetry {"v":2,'
                      '"\\u006disses":{"programs":9}}\n')))
        self.assertFalse(succ.stderr_has_misses(
            write_tmp("kryprobe: telemetry {}\n")))

    def test_strict_loss_duplicate_refuses(self):
        # First-wins would let a later nonzero hide behind
        # an earlier zero — duplicates are contradictory.
        counters = (K6_1_COUNTERS
                    + [("predrop_chase_fail", "1")])
        path = write_tmp(report_doc(
            counters,
            [("ring_drops", "0"), ("overflow_identities", "0")]))
        with self.assertRaises(ValueError):
            succ.parse_loss_counters_strict(path)

    def test_strict_loss_cross_dim_duplicate_refuses(self):
        path = write_tmp(report_doc(
            K6_1_COUNTERS,
            [("ring_drops", "0"), ("overflow_identities", "0"),
             ("predrop_chase_fail", "1")]))
        with self.assertRaises(ValueError):
            succ.parse_loss_counters_strict(path)

    def test_strict_loss_duplicate_member_refuses(self):
        # {"value":1,"value":0} decodes to 0 by default —
        # duplicate members refuse instead.
        doc = ('{"coverage":{"aggregate_counts":{"counters":['
               '{"name":"predrop_chase_fail","value":1,'
               '"value":0}]}}}')
        path = write_tmp(doc)
        with self.assertRaises(ValueError):
            succ.parse_loss_counters_strict(path)

    def test_snapshot_agreement_k6(self):
        reasons = succ.check_snapshot_agreement(
            totals=8990845, snapshot_agg=8990845,
            snapshot_totals=8990845, agg_sum=8990845)
        self.assertEqual(reasons, [])

    def test_snapshot_contradiction_invalid(self):
        reasons = succ.check_snapshot_agreement(
            totals=200, snapshot_agg=1, snapshot_totals=999,
            agg_sum=200)
        self.assertTrue(any("snapshot" in r for r in reasons),
                        reasons)

    def test_agg_rows_unreconciled_invalid(self):
        reasons = succ.check_snapshot_agreement(
            totals=8990845, snapshot_agg=8990845,
            snapshot_totals=8990845, agg_sum=8990844)
        self.assertTrue(any("agg" in r for r in reasons), reasons)

    def test_agg_calls_sum_k6_shape(self):
        agg = {("skcipher", "encrypt", "flat"): {"calls": 99},
               ("skcipher", "decrypt", "flat"): {"calls": 99}}
        alloc = [{"calls": 2}]
        self.assertEqual(succ.agg_calls_sum(agg, alloc), 200)

    def test_agg_calls_sum_refuses_mistyped(self):
        for bad in (True, 9.9, None, -1):
            with self.assertRaises(ValueError, msg=f"calls {bad!r}"):
                succ.agg_calls_sum(
                    {("skcipher", "encrypt", "flat"): {"calls": bad}},
                    [])
        self.assertEqual(succ.agg_calls_sum(
            {("skcipher", "encrypt", "flat"): {"calls": "99"}}, []),
            99)

    def test_strict_loss_counters_k6(self):
        path = write_tmp(report_doc(
            K6_1_COUNTERS,
            [("ring_drops", "0"), ("overflow_identities", "0")]))
        loss = succ.parse_loss_counters_strict(path)
        self.assertEqual(loss["ktot_gap"], 0)
        self.assertEqual(loss["predrop_destroy_skip"], 64)

    def test_strict_loss_counters_refuse_coercion(self):
        # The frozen parser's int() maps False->0 and 0.5->0;
        # the successor loss gate must refuse such evidence.
        for bad in (False, 0.5, "1.5", None):
            counters = [(n, bad if n == "predrop_chase_fail" else v)
                        for n, v in K6_1_COUNTERS]
            path = write_tmp(report_doc(
                counters,
                [("ring_drops", "0"), ("overflow_identities", "0")]))
            with self.assertRaises(ValueError, msg=f"value {bad!r}"):
                succ.parse_loss_counters_strict(path)


class MissTelemetryTests(unittest.TestCase):
    def test_parses_k6_miss_line(self):
        path = write_tmp("noise\n" + K6_1_MISS_LINE)
        miss = succ.parse_miss_telemetry(path)
        self.assertEqual(miss, {"programs": 9, "miss_delta": 22371,
                                "run_delta": None})

    def test_unavailable_refuses(self):
        path = write_tmp('kryprobe: telemetry {"v":1,"misses":'
                         '{"unavailable":true}}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_missing_line_refuses(self):
        path = write_tmp('kryprobe: telemetry {"v":1,"ctx":{"rows":192,'
                         '"present_calls":1,"system_calls":1,'
                         '"unknown_calls":0,"drops":0}}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_mistyped_miss_delta_refuses(self):
        path = write_tmp('kryprobe: telemetry {"v":1,"misses":'
                         '{"programs":9,"miss_delta":true,'
                         '"run_delta":null}}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_malformed_misses_line_refuses_despite_valid(self):
        # A malformed misses-bearing line is a contradictory
        # receipt — it refuses even when another line parsed.
        path = write_tmp(K6_1_MISS_LINE
                         + 'kryprobe: telemetry {"v":1,"misses":'
                         '{"programs":9,\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_null_misses_object_refuses(self):
        path = write_tmp(K6_1_MISS_LINE
                         + 'kryprobe: telemetry {"v":1,'
                         '"misses":null}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_bool_version_refuses(self):
        # True == 1 in Python — the version gate must be
        # type-strict, never ==.
        path = write_tmp('kryprobe: telemetry {"v":true,"misses":'
                         '{"programs":9,"miss_delta":1,'
                         '"run_delta":null}}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_escaped_key_wrong_version_refuses(self):
        # Detection runs on the decoded object, not the raw
        # substring: "\u006disses" decodes to "misses".
        path = write_tmp(K6_1_MISS_LINE
                         + 'kryprobe: telemetry {"v":2,'
                         '"\\u006disses":{"programs":9,'
                         '"miss_delta":5,"run_delta":null}}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_two_miss_terminals_refuse(self):
        # The product prints one terminal line; a second
        # misses object is a contradictory receipt even when
        # both parse (earlier evidence never silently
        # overwritten).
        path = write_tmp(K6_1_MISS_LINE + K6_1_MISS_LINE)
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)

    def test_any_malformed_telemetry_line_refuses(self):
        # Every prefixed line must parse — including escaped
        # forms ("\u006disses") no substring check can see.
        for bad in ('kryprobe: telemetry {"v":1,'
                     '"\\u006disses":\n',
                     'kryprobe: telemetry {"v":1,"ctx":\n'):
            path = write_tmp(K6_1_MISS_LINE + bad)
            with self.assertRaises(ValueError, msg=bad[:40]):
                succ.parse_miss_telemetry(path)

    def test_duplicate_json_members_refuse(self):
        # Default decoding lets a second "misses" member
        # overwrite {"unavailable":true} — duplicates refuse.
        path = write_tmp(
            'kryprobe: telemetry {"v":1,'
            '"misses":{"unavailable":true},'
            '"misses":{"programs":9,"miss_delta":1,'
            '"run_delta":null}}\n')
        with self.assertRaises(ValueError):
            succ.parse_miss_telemetry(path)


GOOD_CTX_LINE = ('kryprobe: telemetry {"v":1,"ctx":{"rows":192,'
                 '"present_calls":200,"system_calls":200,'
                 '"unknown_calls":0,"drops":0}}\n')
BAD_CTX_LINE = ('kryprobe: telemetry {"v":1,"ctx":{"rows":7,'
                '"present_calls":1,"system_calls":999,'
                '"unknown_calls":0,"drops":0}}\n')


class CtxStrictTelemetryTests(unittest.TestCase):
    """F08 (QUAL-02): v3-only strict one-terminal ctx parser.

    The frozen ``m1validity.parse_ctx_telemetry`` last-wins
    repeated objects and skips malformed lines by design (its
    ``test_happy_path_last_wins`` pin stays green); the
    successor path instead requires exactly one valid terminal
    ctx object, an honest version, and unsigned/null counters.
    """

    def test_valid_terminal_control(self):
        # One valid terminal among noise, a tick line, and a
        # miss line parses to exactly the five ctx counters.
        content = ("noise\n"
                   'kryprobe: telemetry {"v":1,"tick":3}\n'
                   + GOOD_CTX_LINE + K6_1_MISS_LINE)
        ctx = succ.parse_ctx_telemetry_strict(write_tmp(content))
        self.assertEqual(ctx, {"rows": 192, "present_calls": 200,
                               "system_calls": 200, "unknown_calls": 0,
                               "drops": 0})

    def test_nulls_allowed(self):
        # An unreadable walk (all null) still parses — the
        # downstream ctx rules name the unreadable operands.
        line = ('kryprobe: telemetry {"v":1,"ctx":{"rows":null,'
                '"present_calls":null,"system_calls":null,'
                '"unknown_calls":null,"drops":null}}\n')
        ctx = succ.parse_ctx_telemetry_strict(write_tmp(line))
        self.assertIsNone(ctx["rows"])
        self.assertIsNone(ctx["drops"])

    def test_identical_duplicate_terminals_refuse(self):
        # Even byte-identical repetition is a contradictory
        # receipt: the product prints one terminal object.
        path = write_tmp(GOOD_CTX_LINE + GOOD_CTX_LINE)
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_contradictory_terminals_both_orders_refuse(self):
        # QUAL-02 repro order (bad then good) and its mirror:
        # neither direction may silently last-win.
        for content in (BAD_CTX_LINE + GOOD_CTX_LINE,
                        GOOD_CTX_LINE + BAD_CTX_LINE):
            path = write_tmp(content)
            with self.assertRaises(ValueError, msg=content[:60]):
                succ.parse_ctx_telemetry_strict(path)

    def test_malformed_ctx_then_valid_refuses(self):
        # A malformed ctx line is never skipped as absent —
        # it refuses even beside a valid terminal.
        path = write_tmp('kryprobe: telemetry {"v":1,"ctx":\n'
                         + GOOD_CTX_LINE)
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_any_malformed_telemetry_line_refuses(self):
        # Every prefixed line must parse strictly (misses
        # convention): truncated/escaped forms included.
        for bad in ('kryprobe: telemetry {"v":1,"ctx":{"rows":\n',
                     'kryprobe: telemetry {"v":1,'
                     '"\\u0063tx":{"rows":1}\n'):
            path = write_tmp(GOOD_CTX_LINE + bad)
            with self.assertRaises(ValueError, msg=bad[:40]):
                succ.parse_ctx_telemetry_strict(path)

    def test_bool_counter_refuses(self):
        # True == 1 in Python — counters must be real ints.
        for bad_key, bad_val in (("rows", True),
                                 ("drops", False),
                                 ("present_calls", True)):
            line = GOOD_CTX_LINE.replace(
                f'"{bad_key}":' +
                ("192" if bad_key == "rows"
                 else "200" if "calls" in bad_key else "0"),
                f'"{bad_key}":' +
                ("true" if bad_val else "false"), 1)
            path = write_tmp(line)
            with self.assertRaises(ValueError,
                                   msg=f"{bad_key}={bad_val!r}"):
                succ.parse_ctx_telemetry_strict(path)

    def test_negative_and_oversized_counter_refuse(self):
        for bad_val in (-1, 2 ** 64):
            line = GOOD_CTX_LINE.replace('"rows":192',
                                         f'"rows":{bad_val}', 1)
            path = write_tmp(line)
            with self.assertRaises(ValueError,
                                   msg=f"rows={bad_val!r}"):
                succ.parse_ctx_telemetry_strict(path)

    def test_float_and_string_counter_refuse(self):
        for bad_val in ("1.5", '"200"'):
            line = GOOD_CTX_LINE.replace('"system_calls":200',
                                         f'"system_calls":{bad_val}',
                                         1)
            path = write_tmp(line)
            with self.assertRaises(ValueError,
                                   msg=f"system_calls={bad_val}"):
                succ.parse_ctx_telemetry_strict(path)

    def test_bool_version_refuses(self):
        path = write_tmp(GOOD_CTX_LINE.replace('{"v":1,',
                                               '{"v":true,', 1))
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_unknown_version_ctx_refuses(self):
        # A ctx-bearing line with v != 1 refuses (miss
        # convention) — it must not read as absent.
        for version in ("2", "0", '"1"', "1.0", "null"):
            line = GOOD_CTX_LINE.replace('{"v":1,',
                                         '{"v":%s,' % version, 1)
            path = write_tmp(line)
            with self.assertRaises(ValueError,
                                   msg=f"v={version!r}"):
                succ.parse_ctx_telemetry_strict(path)

    def test_unknown_version_without_ctx_skipped(self):
        # Non-ctx lines keep miss-parser routing: a wrong
        # version without a ctx member is not ctx evidence.
        content = ('kryprobe: telemetry {"v":2,"tick":9}\n'
                   + GOOD_CTX_LINE)
        ctx = succ.parse_ctx_telemetry_strict(write_tmp(content))
        self.assertEqual(ctx["rows"], 192)

    def test_missing_ctx_refuses(self):
        content = ('kryprobe: telemetry {"v":1,"tick":1}\n'
                   + K6_1_MISS_LINE)
        path = write_tmp(content)
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_null_ctx_object_refuses(self):
        path = write_tmp(GOOD_CTX_LINE
                         + 'kryprobe: telemetry {"v":1,'
                         '"ctx":null}\n')
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_non_dict_ctx_refuses(self):
        path = write_tmp('kryprobe: telemetry {"v":1,'
                         '"ctx":[1,2]}\n')
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_missing_counter_key_refuses(self):
        line = GOOD_CTX_LINE.replace('"drops":0', '"dropped":0', 1)
        path = write_tmp(line)
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_escaped_ctx_key_counts_as_terminal(self):
        # Detection runs on the decoded object: an escaped
        # "\\u0063tx" key decodes to "ctx", so a lone escaped
        # terminal parses and an escaped+plain pair refuses.
        lone = GOOD_CTX_LINE.replace('"ctx":', '"\\u0063tx":', 1)
        ctx = succ.parse_ctx_telemetry_strict(write_tmp(lone))
        self.assertEqual(ctx["rows"], 192)
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(
                write_tmp(GOOD_CTX_LINE + lone))

    def test_duplicate_json_members_refuse(self):
        # Default decoding lets a second "rows" member
        # overwrite the first — duplicates refuse instead.
        path = write_tmp(
            'kryprobe: telemetry {"v":1,"ctx":{"rows":7,'
            '"rows":192,"present_calls":200,"system_calls":200,'
            '"unknown_calls":0,"drops":0}}\n')
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)

    def test_nan_ctx_refuses(self):
        path = write_tmp(
            'kryprobe: telemetry {"v":1,"ctx":NaN}\n')
        with self.assertRaises(ValueError):
            succ.parse_ctx_telemetry_strict(path)


class SuccessorLegTests(unittest.TestCase):
    def leg(self, **over):
        args = {"observed": K6_1["observed"], "truth": K6_1["truth"],
                "report_misses": K6_1["misses"],
                "stderr_miss_delta": K6_1["misses"],
                "ktot_gap": 0, "programs": 9}
        args.update(over)
        return succ.check_successor_leg(**args)

    def test_k6_1_exact_accounted(self):
        self.assertEqual(self.leg(), [])
        self.assertFalse(succ.exact_count_claim(K6_1["misses"]))

    def test_k6_2_exact_accounted(self):
        reasons = succ.check_successor_leg(
            observed=K6_2["observed"], truth=K6_2["truth"],
            report_misses=K6_2["misses"],
            stderr_miss_delta=K6_2["misses"], ktot_gap=0, programs=9)
        self.assertEqual(reasons, [])

    def test_zero_misses_is_exact_count(self):
        reasons = succ.check_successor_leg(
            observed=K6_2["truth"], truth=K6_2["truth"],
            report_misses=0, stderr_miss_delta=0, ktot_gap=0,
            programs=9)
        self.assertEqual(reasons, [])
        self.assertTrue(succ.exact_count_claim(0))

    def test_report_stderr_disagreement_invalid(self):
        reasons = self.leg(stderr_miss_delta=22370)
        self.assertTrue(any("disagree" in r for r in reasons), reasons)

    def test_unexplained_residual_invalid(self):
        reasons = self.leg(observed=K6_1["observed"] - 1)
        self.assertTrue(any("truth" in r for r in reasons), reasons)

    def test_missing_misses_operand_invalid(self):
        reasons = self.leg(report_misses=None, stderr_miss_delta=None)
        self.assertTrue(reasons)

    def test_bool_misses_never_coerced(self):
        reasons = succ.check_successor_leg(
            observed=99, truth=100, report_misses=True,
            stderr_miss_delta=True, ktot_gap=0, programs=9)
        self.assertTrue(reasons)

    def test_negative_misses_invalid(self):
        reasons = self.leg(report_misses=-1, stderr_miss_delta=-1)
        self.assertTrue(reasons)

    def test_old_1m_ktot_lag_invalid_by_gap(self):
        # m1-P-1M-n_cgroup-cr leg00B sealed operands: report
        # totals calls 101494 (KTOT) vs ctx present 101576
        # (Sigma-KCTX) = lag 82; implied misses = truth -
        # present = 103684 - 101576 = 2108. Even crediting
        # those misses, observed + misses != truth, and the
        # lane gap itself invalidates (A12 successor 8(8)).
        reasons = succ.check_successor_leg(
            observed=101494, truth=103684, report_misses=2108,
            stderr_miss_delta=2108, ktot_gap=82, programs=9)
        self.assertTrue(any("ktot_gap" in r for r in reasons), reasons)

    def test_missing_ktot_gap_operand_invalid(self):
        reasons = self.leg(ktot_gap=None)
        self.assertTrue(any("ktot_gap" in r for r in reasons), reasons)

    def test_expected_programs_pin(self):
        self.assertEqual(self.leg(expected_programs=9), [])
        reasons = self.leg(expected_programs=8)
        self.assertTrue(any("programs" in r for r in reasons), reasons)

    def test_digit_string_operands_normalize(self):
        # Serde digit strings are legitimate evidence: they must
        # judge, never crash the checker with TypeError.
        reasons = succ.check_successor_leg(
            observed="8990845", truth="9013216",
            report_misses="22371", stderr_miss_delta=22371,
            ktot_gap="0", programs=9)
        self.assertEqual(reasons, [])


class SuccessorMLegTests(unittest.TestCase):
    # m1-P-4K-n_cgroup-mr leg00B sealed operands (FORENSICS-2):
    # ledger system_total 8607566 + miss_delta 31340 = 8638906.
    PARSED = {"ledger": {"system_total": 8607566}}
    CTX = {"system_calls": 8607566, "present_calls": 8607566,
           "drops": 0}

    def test_forensics_m_leg_truth_exact(self):
        reasons = succ.check_successor_m_leg(
            self.PARSED, self.CTX, miss_delta=31340, truth=8638906,
            programs=9)
        self.assertEqual(reasons, [])

    def test_m_leg_without_miss_operand_invalid(self):
        reasons = succ.check_successor_m_leg(
            self.PARSED, self.CTX, miss_delta=None, truth=8638906,
            programs=9)
        self.assertTrue(reasons)

    def test_m_leg_ctx_system_disagreement_invalid(self):
        ctx = {"system_calls": 8607565, "present_calls": 8607566}
        reasons = succ.check_successor_m_leg(
            self.PARSED, ctx, miss_delta=31340, truth=8638906,
            programs=9)
        self.assertTrue(reasons)

    def test_m_leg_ktot_lag_invalid(self):
        # Same-walk lag: present (Sigma-KCTX) exceeds the ledger
        # system total (KTOT walk) — successor 8(8) gap on M.
        ctx = {"system_calls": 8607566, "present_calls": 8607648,
               "drops": 0}
        reasons = succ.check_successor_m_leg(
            self.PARSED, ctx, miss_delta=31340, truth=8638906,
            programs=9)
        self.assertTrue(any("ktot_gap=82" in r for r in reasons),
                        reasons)

    def test_m_leg_churn_full_saturated_valid(self):
        # Sealed m1-P-4K-churn_full-mr leg00B operands: on
        # saturation the gap operand is present + drops −
        # system (5798 + 7802 − 13600 = 0), never present −
        # system (which misreads attribution overflow as a
        # lane contradiction). Zero misses: exact-count.
        parsed = {"ledger": {"system_total": 13600}}
        ctx = {"system_calls": 13600, "present_calls": 5798,
               "drops": 7802}
        reasons = succ.check_successor_m_leg(
            parsed, ctx, miss_delta=0, truth=13600, programs=9)
        self.assertEqual(reasons, [])
        self.assertTrue(succ.exact_count_claim(0))

    def test_m_leg_digit_string_operands_normalize(self):
        parsed = {"ledger": {"system_total": "8607566"}}
        ctx = {"system_calls": "8607566",
               "present_calls": "8607566", "drops": "0"}
        reasons = succ.check_successor_m_leg(
            parsed, ctx, miss_delta=31340, truth=8638906,
            programs=9)
        self.assertEqual(reasons, [])

    def test_m_leg_malformed_operands_are_reasons(self):
        # Standalone honesty: mistyped/missing ledger/ctx
        # operands invalidate with named reasons, never raise.
        for bad_parsed, bad_ctx in (
                ({"ledger": {}}, self.CTX),
                ({"ledger": {"system_total": True}}, self.CTX),
                (self.PARSED, {"system_calls": None,
                               "present_calls": 8607566}),
                (self.PARSED, {})):
            reasons = succ.check_successor_m_leg(
                bad_parsed, bad_ctx, miss_delta=31340,
                truth=8638906, programs=9)
            self.assertTrue(reasons, (bad_parsed, bad_ctx))


if __name__ == "__main__":
    unittest.main()
