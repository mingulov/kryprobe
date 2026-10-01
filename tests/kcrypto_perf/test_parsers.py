#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the T14 report/ledger/sampler parsers (stdlib only).

Fixtures use the real product shapes observed in T14 preflight
(api-returns JSON rows, lifecycle-session jsonl kinds, the
rss-sampler line format). Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_parsers.py'
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_parsers",
    str(ROOT / "scripts" / "kcrypto_perf" / "parsers.py"))
PARSERS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(PARSERS)


def api_returns_doc(enc=100, dec=100, alloc=1, destroy_skip=1, extra=None):
    def agg(family, op, calls, driver="cbc-aes-aesni", algorithm="cbc(aes)"):
        return {"backend_payload": {
            "row": "agg", "family": family, "op": op, "result": "ok",
            "driver": driver, "algorithm": algorithm,
            "counts": {"calls": calls, "errors": 0, "ok": calls, "queued": 0},
            "bytes": calls * 64}}
    obs = [agg("skcipher", "encrypt", enc), agg("skcipher", "decrypt", dec),
           {"backend_payload": {
               "row": "agg", "family": "any", "op": "alloc", "result": "ok",
               "driver": "", "algorithm": "cbc(aes)",
               "counts": {"calls": alloc, "errors": 0, "ok": alloc,
                          "queued": 0}, "bytes": 0}},
           {"backend_payload": {
               "row": "totals",
               "counts": {"calls": enc + dec + alloc, "errors": 0,
                          "ok": enc + dec + alloc, "queued": 0}, "bytes": 0}}]
    if extra:
        obs.extend(extra)
    return {
        "observations": obs,
        "coverage": {
            "aggregate_counts": {
                "status": "unknown",
                "counters": [
                    {"name": "ktot_gap", "value": "0"},
                    {"name": "predrop_cfg_fail", "value": "0"},
                    {"name": "predrop_fret_fail", "value": "0"},
                    {"name": "predrop_arg_null", "value": "0"},
                    {"name": "predrop_chase_fail", "value": "0"},
                    {"name": "predrop_name_fail", "value": "0"},
                    {"name": "predrop_destroy_skip",
                     "value": str(destroy_skip)},
                    {"name": "predrop_spare_6", "value": "0"},
                    {"name": "predrop_spare_7", "value": "0"},
                    {"name": "uncovered:kernel_delivery_unmeasured",
                     "value": "1"}]},
            "detailed_events": {
                "status": "unknown",
                "counters": [
                    {"name": "ring_drops", "value": "0"},
                    {"name": "overflow_identities", "value": "0"},
                    {"name": "uncovered:kernel_delivery_unmeasured",
                     "value": "1"}]}},
        "verdict": {"status": "partial",
                    "missing": ["capture-integrity", "completion"]}}


def write_tmp(content):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


class ApiReturnsTests(unittest.TestCase):
    def test_enc_dec_alloc(self):
        path = write_tmp(json.dumps(api_returns_doc(92391, 92391)))
        parsed = PARSERS.parse_api_returns(path)
        self.assertEqual(parsed["agg"][("skcipher", "encrypt",
                                        "cbc-aes-aesni")]["calls"], 92391)
        self.assertEqual(parsed["agg"][("skcipher", "decrypt",
                                        "cbc-aes-aesni")]["calls"], 92391)
        self.assertEqual(parsed["alloc_rows"][0]["calls"], 1)
        self.assertEqual(parsed["totals"]["calls"], 184783)

    def test_loss_counters(self):
        path = write_tmp(json.dumps(api_returns_doc()))
        parsed = PARSERS.parse_api_returns(path)
        self.assertEqual(parsed["loss"]["ktot_gap"], 0)
        self.assertEqual(parsed["loss"]["ring_drops"], 0)
        self.assertEqual(parsed["loss"]["overflow_identities"], 0)
        self.assertEqual(parsed["loss"]["predrop_destroy_skip"], 1)
        for site in ("predrop_cfg_fail", "predrop_fret_fail",
                     "predrop_arg_null", "predrop_chase_fail",
                     "predrop_name_fail", "predrop_spare_6",
                     "predrop_spare_7"):
            self.assertEqual(parsed["loss"][site], 0)

    def test_floor_nested_arms_keyed_by_driver(self):
        doc = api_returns_doc()
        doc["observations"].insert(
            1, {"backend_payload": {
                "row": "agg", "family": "skcipher", "op": "encrypt",
                "result": "ok", "driver": "__cbc-aes-aesni",
                "algorithm": "__cbc(aes)",
                "counts": {"calls": 100, "errors": 0, "ok": 100,
                           "queued": 0}, "bytes": 6400}})
        path = write_tmp(json.dumps(doc))
        parsed = PARSERS.parse_api_returns(path)
        self.assertEqual(parsed["agg"][("skcipher", "encrypt",
                                        "__cbc-aes-aesni")]["calls"], 100)
        self.assertEqual(parsed["agg"][("skcipher", "encrypt",
                                        "cbc-aes-aesni")]["calls"], 100)

    def test_who_stack_presence(self):
        doc = api_returns_doc()
        doc["observations"].append({"backend_payload": {
            "row": "who", "comm": "python3", "tgid": 275, "tid": 275,
            "calls": 200, "stack": {"id": 0, "frames": []}}})
        path = write_tmp(json.dumps(doc))
        parsed = PARSERS.parse_api_returns(path)
        self.assertEqual(len(parsed["who"]), 1)
        self.assertEqual(parsed["who"][0]["stack"]["id"], 0)
        self.assertEqual(parsed["who"][0]["stack"]["frames"], [])

    def test_missing_file_raises(self):
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_api_returns(Path("/nonexistent-t14/report.json"))

    def test_bad_json_raises(self):
        path = write_tmp("{not json")
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_api_returns(path)


class LifecycleTests(unittest.TestCase):
    def _write_lc(self, n_obs, receipt_overrides=None, terminal="sync"):
        lines = ['{"kind":"session_start","seq":1}']
        for i in range(1, n_obs + 1):
            lines.append(json.dumps(
                {"kind": "observation", "seq": i + 1,
                 "record": {"request_id": f"lc:{i}", "status": 0,
                           "terminal": terminal, "duration_ns": "50000",
                           "tfm_id": "kcrypto:tfm-1"}}))
        receipt = {"kind": "session_receipt", "seq": n_obs + 3,
                   "verdict": "partial", "truncated": False,
                   "admitted": n_obs, "emitted": n_obs, "unfinished": 0,
                   "loss": {}}
        receipt.update(receipt_overrides or {})
        lines.append('{"kind":"coverage","seq":%d,"admitted":%d,"emitted":%d,'
                     '"unfinished":0,"loss":{},"unknown":0,"filtered":0}'
                     % (n_obs + 2, n_obs, n_obs))
        lines.append(json.dumps(receipt))
        return write_tmp("\n".join(lines) + "\n")

    def test_clean_counts(self):
        parsed = PARSERS.parse_lifecycle(self._write_lc(216))
        self.assertEqual(parsed["observations"], 216)
        self.assertEqual(parsed["receipt"]["emitted"], 216)
        self.assertEqual(parsed["receipt"]["admitted"], 216)
        self.assertFalse(parsed["receipt"]["truncated"])
        self.assertEqual(parsed["receipt"]["unfinished"], 0)
        self.assertEqual(parsed["receipt"]["loss"], {})
        self.assertEqual(parsed["terminals"], {"sync": 216})

    def test_truncated_receipt(self):
        parsed = PARSERS.parse_lifecycle(
            self._write_lc(100000, {"verdict": "partial", "truncated": True,
                                    "admitted": 100001, "emitted": 100001,
                                    "loss": {"driver.omitted": 1}}))
        self.assertTrue(parsed["receipt"]["truncated"])
        self.assertEqual(parsed["receipt"]["loss"], {"driver.omitted": 1})

    def test_async_unknown_terminals(self):
        parsed = PARSERS.parse_lifecycle(
            self._write_lc(10, {"unfinished": 10}, terminal="unknown"))
        self.assertEqual(parsed["terminals"], {"unknown": 10})
        self.assertEqual(parsed["receipt"]["unfinished"], 10)

    def test_missing_receipt_raises(self):
        path = write_tmp('{"kind":"session_start","seq":1}\n')
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_lifecycle(path)


class SamplerTests(unittest.TestCase):
    def test_rss_max_and_cpu(self):
        content = ("clk_tck=100\n"
                   "t=100 rss_kb=12000 utime=50 stime=10\n"
                   "t=101 rss_kb=15000 utime=150 stime=20\n"
                   "t=102 rss_kb=13000 utime=250 stime=30\n")
        path = write_tmp(content)
        parsed = PARSERS.parse_sampler(path)
        self.assertEqual(parsed["rss_max_kb"], 15000)
        self.assertAlmostEqual(parsed["cpu_s"], 2.2)
        self.assertEqual(parsed["samples"], 3)

    def test_single_sample_cpu_zero(self):
        path = write_tmp("clk_tck=100\nt=100 rss_kb=12000 utime=50 stime=10\n")
        parsed = PARSERS.parse_sampler(path)
        self.assertEqual(parsed["cpu_s"], 0.0)

    def test_empty_raises(self):
        path = write_tmp("clk_tck=100\n")
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_sampler(path)


class LedgerCsvTests(unittest.TestCase):
    def test_rows_and_header(self):
        content = ("seq,phase,op,dt_ns\n"
                   "0,meas,encrypt,43000\n"
                   "0,meas,decrypt,15000\n"
                   "1,meas,encrypt,44000\n"
                   "1,meas,decrypt,16000\n")
        path = write_tmp(content)
        rows = PARSERS.parse_ledger_csv(path)
        self.assertEqual(rows, [(0, "meas", "encrypt", 43000),
                                (0, "meas", "decrypt", 15000),
                                (1, "meas", "encrypt", 44000),
                                (1, "meas", "decrypt", 16000)])

    def test_bad_header_raises(self):
        path = write_tmp("a,b,c\n1,2,3\n")
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_ledger_csv(path)

    def test_bad_row_raises(self):
        path = write_tmp("seq,phase,op,dt_ns\n0,meas,encrypt,xx\n")
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_ledger_csv(path)


class TelemetryTests(unittest.TestCase):
    # R1 gap closure: machine-readable `kryprobe: telemetry {...}`
    # stderr lines (drain lag, stop spans, occupancy). Best-effort
    # observability: malformed lines are counted, never fatal;
    # a missing file is a ParseError (module discipline).
    PREFIX = "kryprobe: telemetry "

    def _line(self, obj):
        import json as _json
        return self.PREFIX + _json.dumps(obj) + "\n"

    def test_ticks_fold_to_max_lag(self):
        content = ("kryprobe: progress tick=1 rows=3 drops=0\n"
                   + self._line({"v": 1, "tick": 1, "lagmax_us": 120})
                   + self._line({"v": 1, "tick": 2, "lagmax_us": 95})
                   + self._line({"v": 1, "tick": 3, "lagmax_us": 310}))
        parsed = PARSERS.parse_telemetry(write_tmp(content))
        self.assertEqual(parsed["lagmax_us"], 310)
        self.assertEqual(parsed["lines"], 3)
        self.assertEqual(parsed["malformed"], 0)
        self.assertIsNone(parsed["stop"])
        self.assertIsNone(parsed["occupancy"])

    def test_stop_occupancy_last_wins(self):
        stop = {"total_us": 42000, "detach_us": 3000,
                "snapshot_us": 9000, "render_us": 30000}
        occ = {"kagg": 4, "ktot": 1, "kidn": 4, "kwho": 2,
               "kstack": 1, "kerr": 0, "kparams": 1, "kdrops": 8,
               "kring_pending": None}
        content = (self._line({"v": 1, "stop": {"total_us": 1},
                                "occupancy": {"kagg": 0}})
                   + self._line({"v": 1, "stop": stop,
                                 "occupancy": occ}))
        parsed = PARSERS.parse_telemetry(write_tmp(content))
        self.assertEqual(parsed["stop"], stop)
        self.assertEqual(parsed["occupancy"], occ)

    def test_malformed_counted_never_fatal(self):
        content = (self.PREFIX + "{not json\n"
                   + self._line({"v": 99, "tick": 1, "lagmax_us": 5})
                   + self._line({"v": 1, "tick": 2, "lagmax_us": 7}))
        parsed = PARSERS.parse_telemetry(write_tmp(content))
        self.assertEqual(parsed["malformed"], 2)
        self.assertEqual(parsed["lagmax_us"], 7)

    def test_empty_gives_nones(self):
        parsed = PARSERS.parse_telemetry(
            write_tmp("kryprobe: progress tick=1 rows=0 drops=0\n"))
        self.assertIsNone(parsed["lagmax_us"])
        self.assertIsNone(parsed["stop"])
        self.assertIsNone(parsed["occupancy"])
        self.assertEqual(parsed["lines"], 0)

    def test_missing_file_raises(self):
        with self.assertRaises(PARSERS.ParseError):
            PARSERS.parse_telemetry(
                write_tmp("x").parent / "definitely-missing.log")


if __name__ == "__main__":
    unittest.main()
