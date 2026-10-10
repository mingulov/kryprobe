#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for M1 M-mode gap closure (Task05 Stage 4, freeze G1-G11).

Manifest M observer + final 40-set manifest, metadata staging/pins,
workload-json judge extension, per-leg M-active proof, the 0.80 4K
floor, unknown-fraction reporting, M-activity evidence, the campaign
metadata file, and Docker-lab/A25 journey self-checks. Run from the
product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_m1m.py'
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_cli",
    str(ROOT / "scripts" / "kcrypto-perf.py"))
CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CLI)

from kcrypto_perf import m1manifest, m1validity  # noqa: E402
from kcrypto_perf import parsers as kparsers  # noqa: E402

M1_MANIFEST = ROOT / "tests" / "kcrypto_perf" / "cells-m1.json"
M1_METADATA = ROOT / "tests" / "fixtures" / "kcrypto_m1_metadata.json"
WORKLOAD_LAB = ROOT / "scripts" / "workload-lab"


def write_tmp(content, suffix=""):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return Path(fh.name)


def _wreport(system=100, perctx=100, refused=0, status="available",
            reason=None, calls=(60, 30, 10), consistency="unproven",
            gap=True, unknown=0, metadata_cov="complete",
            attribution="complete", profile="api-returns",
            sys_sat=False, pctx_sat=False):
    """Minimal workload-report-v2 doc (campaign M-leg shape)."""
    rows = [{"kh": str(1000 + i), "cgroup_id": str(2000 + i),
             "tgid": 100 + i, "uid": 1000, "start_ns": "1",
             "execution_kind": "proc", "calls": str(calls[i])}
            for i in range(len(calls))]
    matched = sum(calls)
    metadata = {"status": status}
    if reason is not None:
        metadata["reason"] = reason
    return {
        "schema": "kryprobe.workload-report.v2",
        "session": {"session_id": "a" * 32,
                    "kernel_identity": "7.0.14/test"},
        "interval": {"start_ns": "1", "end_ns": "2",
                     "consistency": consistency,
                     "clock": "monotonic_boot"},
        "profile": profile, "boundary": "api_return",
        "dictionary": [], "contexts": rows,
        "ledger": {"system_total": str(system),
                   "per_context_sum": str(perctx),
                   "unknown": str(unknown),
                   "consistency": consistency,
                   "gap_unreconciled": gap,
                   "system_saturated": sys_sat,
                   "per_context_saturated": pctx_sat,
                   "refused_inserts": str(refused)},
        "partition": {"matched": str(matched), "nonmatched": "0",
                      "unknown_match": "0"},
        "selectors": {"kind": "none"},
        "scope": {"capture_scope": "system", "report_scope": "unscoped",
                  "group_by": "none"},
        "metadata": metadata,
        "coverage": {"capture": "partial", "attribution": attribution,
                     "metadata": metadata_cov,
                     "correlation": "complete"},
    }


def _ctx(rows=2, present=100, system=100, unknown=0, drops=0):
    return {"rows": rows, "present_calls": present,
            "system_calls": system, "unknown_calls": unknown,
            "drops": drops}


def _api_report(totals_calls=100, overflow="0"):
    loss = ["ktot_gap", "ring_drops", "overflow_identities",
            "predrop_cfg_fail", "predrop_fret_fail",
            "predrop_arg_null", "predrop_chase_fail",
            "predrop_name_fail", "predrop_destroy_skip",
            "predrop_spare_6", "predrop_spare_7"]
    counters = [{"name": name, "value": "0"} for name in loss]
    counters.append({"name": "ctx_overflow_identities",
                     "value": overflow})
    return {"observations": [
        {"backend_payload": {"row": "totals",
                             "counts": {"calls": totals_calls}}}],
        "coverage": {
            "aggregate_counts": {"counters": counters[:1]},
            "detailed_events": {"counters": counters}},
        "verdict": {"status": "complete"}}


class MLoaderTests(unittest.TestCase):
    """G1: the manifest loader knows the M observer."""

    def _manifest_with_m(self):
        manifest = m1manifest.load_manifest(M1_MANIFEST)
        manifest["sets"][0]["obs_b"] = "M"
        return write_tmp(json.dumps(
            {k: v for k, v in manifest.items()
             if not k.startswith("_")}))

    def test_obs_m_accepted(self):
        manifest = m1manifest.load_manifest(self._manifest_with_m())
        self.assertEqual(manifest["sets"][0]["obs_b"], "M")

    def test_side_b_error_names_m(self):
        manifest = m1manifest.load_manifest(M1_MANIFEST)
        manifest["sets"][0]["obs_b"] = "D"
        manifest["sets"][0]["mode_b"] = "disabled"
        path = write_tmp(json.dumps(
            {k: v for k, v in manifest.items()
             if not k.startswith("_")}))
        with self.assertRaises(m1manifest.InputError) as ctx:
            m1manifest.load_manifest(path)
        self.assertIn("M", str(ctx.exception))

    def test_unknown_obs_still_refused(self):
        manifest = m1manifest.load_manifest(M1_MANIFEST)
        manifest["sets"][0]["obs_b"] = "X"
        path = write_tmp(json.dumps(
            {k: v for k, v in manifest.items()
             if not k.startswith("_")}))
        with self.assertRaises(m1manifest.InputError):
            m1manifest.load_manifest(path)


class FinalManifestTests(unittest.TestCase):
    """G10: the final 40-set manifest (+1 diag)."""

    def setUp(self):
        self.manifest = m1manifest.load_manifest(M1_MANIFEST)

    def test_forty_sets_plus_diag(self):
        self.assertEqual(len(self.manifest["sets"]), 40)
        self.assertEqual(len(self.manifest["diagnostics"]), 1)

    def test_manifest_version_two(self):
        self.assertEqual(self.manifest["manifest_version"], 2)

    def test_mr_md_sets_per_group(self):
        ids = {entry["id"] for entry in self.manifest["sets"]}
        for cls in ("P-4K", "P-1M"):
            for workload in ("single", "n_cgroup", "churn_below",
                             "churn_full"):
                self.assertIn(f"m1-{cls}-{workload}-mr", ids)
                self.assertIn(f"m1-{cls}-{workload}-md", ids)

    def test_mr_shape(self):
        entry = CLI.find_set(self.manifest, "m1-P-1M-single-mr")
        self.assertEqual((entry["obs_a"], entry["mode_a"]),
                         ("R", "aggregation"))
        self.assertEqual((entry["obs_b"], entry["mode_b"]),
                         ("M", "aggregation"))
        self.assertTrue(entry["budgeted"])
        self.assertEqual((entry["pairs"], entry["max_attempted"]),
                         (10, 12))

    def test_md_shape(self):
        entry = CLI.find_set(self.manifest, "m1-P-1M-n_cgroup-md")
        self.assertEqual((entry["obs_a"], entry["mode_a"]),
                         ("D", "disabled"))
        self.assertEqual((entry["obs_b"], entry["mode_b"]),
                         ("M", "aggregation"))
        self.assertEqual((entry["pairs"], entry["max_attempted"]),
                         (10, 12))

    def test_1m_cd_budgeted_flip(self):
        for workload in ("single", "n_cgroup", "churn_below",
                         "churn_full"):
            entry = CLI.find_set(self.manifest,
                                 f"m1-P-1M-{workload}-cd")
            self.assertTrue(entry["budgeted"], entry["id"])

    def test_1m_md_budgeted_4k_envelope(self):
        for workload in ("single", "n_cgroup", "churn_below",
                         "churn_full"):
            budgeted = CLI.find_set(
                self.manifest, f"m1-P-1M-{workload}-md")
            self.assertTrue(budgeted["budgeted"], budgeted["id"])
            envelope = CLI.find_set(
                self.manifest, f"m1-P-4K-{workload}-md")
            self.assertFalse(envelope["budgeted"], envelope["id"])

    def test_4k_cd_stays_envelope(self):
        for workload in ("single", "n_cgroup", "churn_below",
                         "churn_full"):
            entry = CLI.find_set(self.manifest,
                                 f"m1-P-4K-{workload}-cd")
            self.assertFalse(entry["budgeted"], entry["id"])

    def test_cr_rd_shapes_preserved(self):
        entry = CLI.find_set(self.manifest, "m1-P-4K-single-cr")
        self.assertTrue(entry["budgeted"])
        self.assertEqual((entry["pairs"], entry["max_attempted"]),
                         (10, 12))
        entry = CLI.find_set(self.manifest, "m1-P-1M-churn_full-rd")
        self.assertFalse(entry["budgeted"])
        self.assertEqual((entry["pairs"], entry["max_attempted"]),
                         (5, 8))


def _m1_stage_cell(tmp, obs_a="R", obs_b="M", with_metadata=True,
                   with_helper=True, guest_metadata="MATCH",
                   guest_helper="MATCH"):
    """Minimal synthetic M1 cell dir + stage dict for pin checks."""
    import hashlib

    cell = Path(tmp) / "cell-m"
    pins = {}

    def _file(rel, content=b"x"):
        target = cell / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content + rel.encode())
        pins[rel] = hashlib.sha256(target.read_bytes()).hexdigest()
        return pins[rel]

    for name in sorted(CLI.M1_BASE_PINS):
        if name == "kcrypto_fixture.ko":
            pins[name] = "none"
        else:
            _file(name)
    for side, role in (("A", obs_a), ("B", obs_b)):
        if role == "D":
            _file(f"obs-{side}/DISABLED")
            continue
        for tail in CLI.M1_OBS_PINS:
            _file(f"obs-{side}/{tail}")
        if role == "M":
            if with_metadata:
                _file(f"obs-{side}/workload-metadata.json")
            if with_helper:
                _file(f"obs-{side}/kryprobe-workload-helper")
    env = {"ko": "none", "driver": pins["kcrypto_perf.py"]}
    for side in ("a", "b"):
        for dim, tail in (("kryprobe", "kryprobe"),
                          ("agg", "kryprobe-bpf/kcrypto.bpf.o"),
                          ("lc",
                           "kryprobe-bpf/kcrypto-lifecycle.bpf.o")):
            pin = pins.get(f"obs-{side.upper()}/{tail}")
            if pin is not None:
                env[f"obs_{side}_{dim}"] = pin
        meta = pins.get(f"obs-{side.upper()}/workload-metadata.json")
        if meta is not None:
            env[f"obs_{side}_metadata"] = (
                meta if guest_metadata == "MATCH" else "0" * 64)
        helper = pins.get(
            f"obs-{side.upper()}/kryprobe-workload-helper")
        if helper is not None:
            env[f"obs_{side}_helper"] = (
                helper if guest_helper == "MATCH" else "0" * 64)
    (cell / "environment.txt").write_text(
        "".join(f"{key}={val}\n" for key, val in sorted(env.items())))
    stage = {"sha256": dict(pins), "obs_a": obs_a, "obs_b": obs_b}
    return cell, stage


class MetadataStagingTests(unittest.TestCase):
    """G2/G5: metadata staging pins + stage-pin check + guest hashes."""

    def test_pin_check_accepts_m_role(self):
        tmp = tempfile.mkdtemp()
        cell, stage = _m1_stage_cell(tmp)
        reasons, _ = CLI.check_m1_stage_pins(cell, stage)
        self.assertEqual(reasons, [])

    def test_pin_check_requires_metadata_pin(self):
        tmp = tempfile.mkdtemp()
        cell, stage = _m1_stage_cell(tmp, with_metadata=False)
        reasons, _ = CLI.check_m1_stage_pins(cell, stage)
        self.assertTrue(any("workload-metadata.json" in reason
                            for reason in reasons), reasons)

    def test_pin_check_requires_helper_pin(self):
        tmp = tempfile.mkdtemp()
        cell, stage = _m1_stage_cell(tmp, with_helper=False)
        reasons, _ = CLI.check_m1_stage_pins(cell, stage)
        self.assertTrue(any("kryprobe-workload-helper" in reason
                            for reason in reasons), reasons)

    def test_pin_check_guest_metadata_hash(self):
        tmp = tempfile.mkdtemp()
        cell, stage = _m1_stage_cell(tmp, guest_metadata="MISMATCH")
        reasons, _ = CLI.check_m1_stage_pins(cell, stage)
        self.assertTrue(any("obs_b_metadata" in reason
                            for reason in reasons), reasons)

    def test_pin_check_guest_helper_hash(self):
        tmp = tempfile.mkdtemp()
        cell, stage = _m1_stage_cell(tmp, guest_helper="MISMATCH")
        reasons, _ = CLI.check_m1_stage_pins(cell, stage)
        self.assertTrue(any("obs_b_helper" in reason
                            for reason in reasons), reasons)

    def test_pin_check_unknown_role_still_refused(self):
        tmp = tempfile.mkdtemp()
        cell, stage = _m1_stage_cell(tmp, obs_b="C")
        stage["obs_b"] = "X"
        reasons, _ = CLI.check_m1_stage_pins(cell, stage)
        self.assertTrue(any("unknown" in reason for reason in reasons),
                        reasons)

    def test_metadata_arg_required_for_m(self):
        with self.assertRaises(CLI.owned_guest.GuestError):
            CLI.m1_stage_metadata_args({"A": "R", "B": "M"}, None)

    def test_metadata_arg_refused_without_m(self):
        with self.assertRaises(CLI.owned_guest.GuestError):
            CLI.m1_stage_metadata_args({"A": "R", "B": "C"},
                                       "/tmp/meta.json")

    def test_metadata_arg_ok(self):
        self.assertEqual(
            CLI.m1_stage_metadata_args({"A": "R", "B": "M"},
                                       "/tmp/meta.json"),
            "/tmp/meta.json")

    def _stage_m_cell(self, with_helper=True):
        import os
        from types import SimpleNamespace
        from unittest import mock

        tmp = Path(tempfile.mkdtemp())
        home = tmp / "home"
        boot = home / ".cache" / "virtme-ng" / "vX" / "amd64" / "boot"
        boot.mkdir(parents=True)
        (boot / "config-test").write_text("guest-config-bytes")
        bin_d = tmp / "bin"
        (bin_d / "bpf").mkdir(parents=True)
        (bin_d / "kryprobe").write_bytes(b"fake-cli")
        (bin_d / "bpf" / "kcrypto.bpf.o").write_bytes(b"agg")
        (bin_d / "bpf" / "kcrypto-lifecycle.bpf.o").write_bytes(b"lc")
        if with_helper:
            (bin_d / "kryprobe-workload-helper").write_bytes(
                b"helper")
        meta = {"collector": "test",
                "snapshot_interval": {"start_ns": 0, "end_ns": 1},
                "kernel_identity": "unknown", "entries": []}
        (tmp / "meta.json").write_text(json.dumps(meta))
        (tmp / "driver.py").write_bytes(b"driver")
        entry = {"id": "fake-mr", "kernel": "7.0.14",
                 "workload": "single", "obs_a": "R", "obs_b": "M",
                 "pairs": 10, "max_attempted": 12}
        manifest = {
            "global": {"warmup_s": 10, "measure_s": 30,
                       "capture_s": 50, "settle_s": 5,
                       "quiet_s": 5},
            "workloads": {"single": {"driver_flags": "",
                                     "driver_threads": 1,
                                     "expected_rows": 3}}}
        legs = [{"leg_id": f"leg00{side}", "side": side,
                 "mode": "aggregation", "cls": "P-4K",
                 "driver": "skcipher", "size": 4096,
                 "workload": "single", "paced": 0, "bulk": 0,
                 "threads": 1} for side in ("A", "B")]
        args = SimpleNamespace(
            out_root=str(tmp / "out"),
            obs_a=f"{bin_d}/kryprobe:{bin_d}/bpf",
            obs_b=f"{bin_d}/kryprobe:{bin_d}/bpf",
            metadata=str(tmp / "meta.json"),
            driver=str(tmp / "driver.py"))
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            return CLI.stage_m1_run_dir(
                args, entry, manifest, "set", "MANIFESTSHA", "vX",
                legs, "fake-mr")

    def test_stage_m_side_copies_and_pins(self):
        run_dir, stage, _ = self._stage_m_cell()
        self.assertTrue(
            (run_dir / "obs-B" / "workload-metadata.json").is_file())
        self.assertTrue(
            (run_dir / "obs-B" /
             "kryprobe-workload-helper").is_file())
        self.assertFalse(
            (run_dir / "obs-A" / "workload-metadata.json").exists())
        set_env = (run_dir / "set.env").read_text()
        self.assertIn("OBS_A=R", set_env)
        self.assertIn("OBS_B=M", set_env)
        self.assertIn("METADATA_SHA=", set_env)
        self.assertNotIn("METADATA_SHA=none", set_env)
        pins_env = (run_dir / "pins.env").read_text()
        self.assertIn("META_B_SHA=", pins_env)
        self.assertIn("HELPER_B_SHA=", pins_env)
        self.assertIsNotNone(stage["metadata_sha256"])
        # Round trip: a guest env echoing the staged pins passes
        # the pin check (the scenario writes these dims in-guest).
        pins = stage["sha256"]
        env = {"ko": "none", "driver": pins["kcrypto_perf.py"]}
        for side in ("a", "b"):
            for dim, tail in (("kryprobe", "kryprobe"),
                              ("agg", "kryprobe-bpf/kcrypto.bpf.o"),
                              ("lc", "kryprobe-bpf/kcrypto-lifecycle"
                                     ".bpf.o"),
                              ("metadata", "workload-metadata.json"),
                              ("helper",
                               "kryprobe-workload-helper")):
                pin = pins.get(f"obs-{side.upper()}/{tail}")
                if pin is not None:
                    env[f"obs_{side}_{dim}"] = pin
        (run_dir / "environment.txt").write_text(
            "".join(f"{key}={val}\n"
                    for key, val in sorted(env.items())))
        reasons, _ = CLI.check_m1_stage_pins(run_dir, stage)
        self.assertEqual(reasons, [])

    def test_stage_m_side_missing_helper_refused(self):
        with self.assertRaises(CLI.owned_guest.GuestError):
            self._stage_m_cell(with_helper=False)


class WorkloadParseTests(unittest.TestCase):
    """G4: workload-json report parsing (totals/loss/coverage)."""

    def test_happy_path(self):
        parsed = kparsers.parse_workload_report(
            write_tmp(json.dumps(_wreport())))
        self.assertEqual(parsed["ledger"]["system_total"], 100)
        self.assertEqual(parsed["ledger"]["per_context_sum"], 100)
        self.assertEqual(parsed["ledger"]["refused_inserts"], 0)
        self.assertTrue(parsed["ledger"]["gap_unreconciled"])
        self.assertEqual(parsed["metadata"]["status"], "available")
        self.assertEqual(parsed["coverage"]["capture"], "partial")
        self.assertEqual(parsed["n_rows"], 3)
        self.assertEqual(parsed["rows_calls_sum"], 100)

    def test_schema_refused(self):
        doc = _wreport()
        doc["schema"] = "kryprobe.workload-report.v1"
        with self.assertRaises(kparsers.ParseError):
            kparsers.parse_workload_report(write_tmp(json.dumps(doc)))

    def test_mistyped_counters_refused(self):
        for bad in ("seven", "-3", "3.0", "", None, True, 1.5):
            doc = _wreport()
            doc["ledger"]["system_total"] = bad
            with self.assertRaises(kparsers.ParseError, msg=repr(bad)):
                kparsers.parse_workload_report(
                    write_tmp(json.dumps(doc)))

    def test_missing_ledger_refused(self):
        doc = _wreport()
        del doc["ledger"]
        with self.assertRaises(kparsers.ParseError):
            kparsers.parse_workload_report(write_tmp(json.dumps(doc)))

    def test_unreadable_refused(self):
        with self.assertRaises(kparsers.ParseError):
            kparsers.parse_workload_report(
                Path("/nonexistent/report.workload-json"))


class MLegValidityTests(unittest.TestCase):
    """G4/G6: M-leg observer checks + the C-leg-as-M hole."""

    def _m_cell(self, report, ctx, m_evidence=None, api_report=None):
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        line = ("kryprobe: telemetry "
                + json.dumps({"v": 1, "ctx": ctx}) + "\n")
        (legs / "leg00B-capture.stderr.log").write_text(line)
        if report is not None:
            (legs / "leg00B-report.workload-json").write_text(
                json.dumps(report))
        if api_report is not None:
            (legs / "leg00B-report.json").write_text(
                json.dumps(api_report))
        if m_evidence is not None:
            (legs / "leg00B-m.json").write_text(
                json.dumps(m_evidence))
        return tmp

    def _judged(self):
        return {"leg_id": "leg00B", "valid": True, "outcome": "valid",
                "reasons": [], "driver": {"rc": 0}}

    def _leg(self):
        return {"leg_id": "leg00B", "side": "B",
                "mode": "aggregation", "workload": "single"}

    def _entry(self, obs="M"):
        return {"kind": "m1-pairs", "obs_a": "R", "obs_b": obs}

    def _manifest(self):
        return {"workloads": {"single": {"expected_rows": 3},
                             "churn_full": {"expected_rows": 1024}}}

    def test_c_leg_as_m_is_invalid(self):
        # G6 hole (RED): an M-role leg run without the metadata
        # path is byte-identical to a C leg (api-returns report,
        # no workload-json) — the judge must refuse it as M.
        cell = self._m_cell(None, _ctx(3, 100, 100, 0, 0),
                            api_report=_api_report(100))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("M"),
                                       self._manifest())
        self.assertFalse(out["valid"])
        self.assertTrue(any("workload-json" in reason
                            for reason in out["reasons"]),
                        out["reasons"])

    def test_m_unavailable_metadata_invalid(self):
        report = _wreport(status="unavailable",
                          reason="no_principal")
        cell = self._m_cell(report, _ctx(3, 100, 100, 0, 0))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("M"),
                                       self._manifest())
        self.assertFalse(out["valid"])
        self.assertTrue(any("metadata" in reason
                            for reason in out["reasons"]),
                        out["reasons"])

    def test_m_happy_path(self):
        report = _wreport(system=100, perctx=100)
        cell = self._m_cell(report, _ctx(3, 100, 100, 0, 0))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("M"),
                                       self._manifest())
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_m_ledger_ctx_contradiction_invalid(self):
        # Same-walk operands disagree (flaky-KTOT class): invalid
        # with the contradiction named, never averaged away.
        report = _wreport(system=100, perctx=100)
        cell = self._m_cell(report, _ctx(3, 100, 120, 20, 20))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("M"),
                                       self._manifest())
        self.assertFalse(out["valid"])

    def test_m_refused_must_match_drops(self):
        report = _wreport(system=100, perctx=100, refused=5)
        cell = self._m_cell(report, _ctx(3, 100, 100, 0, 0))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("M"),
                                       self._manifest())
        self.assertFalse(out["valid"])
        self.assertTrue(any("refused" in reason
                            for reason in out["reasons"]),
                        out["reasons"])

    def test_m_churn_full_overflow_equivalent(self):
        ctx = {"rows": 1024, "present_calls": 9000,
               "system_calls": 10000, "unknown_calls": 1000,
               "drops": 1000}
        calls = tuple([9] * 808 + [8] * 216)
        self.assertEqual((len(calls), sum(calls)), (1024, 9000))
        report = _wreport(system=10000, perctx=9000,
                          refused=1000, calls=calls)
        cell = self._m_cell(report, ctx)
        judged = self._judged()
        leg = dict(self._leg(), workload="churn_full")
        out = CLI.apply_m1_ctx_overlay(cell, judged, leg,
                                       self._entry("M"),
                                       self._manifest())
        self.assertTrue(out["valid"], out.get("reasons"))

    def test_m_churn_full_silent_overflow_invalid(self):
        ctx = {"rows": 1024, "present_calls": 10000,
               "system_calls": 10000, "unknown_calls": 0,
               "drops": 0}
        calls = tuple([10] * 784 + [9] * 240)
        self.assertEqual((len(calls), sum(calls)), (1024, 10000))
        report = _wreport(system=10000, perctx=10000,
                          refused=0, calls=calls)
        cell = self._m_cell(report, ctx)
        judged = self._judged()
        leg = dict(self._leg(), workload="churn_full")
        out = CLI.apply_m1_ctx_overlay(cell, judged, leg,
                                       self._entry("M"),
                                       self._manifest())
        self.assertFalse(out["valid"])

    def test_c_leg_with_workload_json_invalid(self):
        # Mixup mirror: a C-role leg carrying an M report (M
        # staged as C) must fail loudly.
        cell = self._m_cell(_wreport(), _ctx(3, 100, 100, 0, 0),
                            api_report=_api_report(100))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("C"),
                                       self._manifest())
        self.assertFalse(out["valid"])
        self.assertTrue(any("workload-json" in reason
                            for reason in out["reasons"]),
                        out["reasons"])

    def test_c_leg_unchanged(self):
        # Control: the C path still judges C-shaped evidence.
        cell = self._m_cell(None, _ctx(3, 100, 100, 0, 0),
                            api_report=_api_report(100))
        out = CLI.apply_m1_ctx_overlay(cell, self._judged(),
                                       self._leg(), self._entry("C"),
                                       self._manifest())
        self.assertTrue(out["valid"], out.get("reasons"))


class MEvidenceTests(unittest.TestCase):
    """G6: per-leg M-active proof (sealed launch audit)."""

    def _cell(self, evidence):
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        if evidence is not None:
            (legs / "leg00B-m.json").write_text(json.dumps(evidence))
        return tmp

    def _stage(self, meta="m" * 64, helper="h" * 64):
        return {"obs_a": "R", "obs_b": "M",
                "sha256": {"obs-B/workload-metadata.json": meta,
                           "obs-B/kryprobe-workload-helper": helper}}

    def _leg(self):
        return {"leg_id": "leg00B", "side": "B",
                "mode": "aggregation"}

    def _entry(self):
        return {"kind": "m1-pairs", "obs_a": "R", "obs_b": "M"}

    def _evidence(self, meta="m" * 64, helper="h" * 64, uid=1000):
        return {"schema": "kryprobe-m1-mleg/v1", "leg_id": "leg00B",
                "side": "B", "obs": "M",
                "metadata_sha256": meta,
                "helper_sha256": helper, "principal_uid": uid}

    def test_happy_path(self):
        evidence = self._evidence()
        cell = self._cell(evidence)
        self.assertEqual(
            CLI.check_m_evidence(cell, self._leg(), self._entry(),
                                 self._stage()), [])

    def test_missing_evidence_invalid(self):
        cell = self._cell(None)
        reasons = CLI.check_m_evidence(cell, self._leg(),
                                       self._entry(), self._stage())
        self.assertTrue(any("m.json" in reason for reason in reasons),
                        reasons)

    def test_metadata_sha_mismatch_invalid(self):
        evidence = self._evidence(meta="0" * 64)
        cell = self._cell(evidence)
        reasons = CLI.check_m_evidence(cell, self._leg(),
                                       self._entry(), self._stage())
        self.assertTrue(any("metadata_sha256" in reason
                            for reason in reasons), reasons)

    def test_helper_sha_mismatch_invalid(self):
        evidence = self._evidence(helper="0" * 64)
        cell = self._cell(evidence)
        reasons = CLI.check_m_evidence(cell, self._leg(),
                                       self._entry(), self._stage())
        self.assertTrue(any("helper_sha256" in reason
                            for reason in reasons), reasons)

    def test_root_principal_invalid(self):
        # M legs must run as non-root (else no_principal and the
        # helper never launches): uid 0 fails the evidence check.
        evidence = self._evidence(uid=0)
        cell = self._cell(evidence)
        reasons = CLI.check_m_evidence(cell, self._leg(),
                                       self._entry(), self._stage())
        self.assertTrue(any("uid" in reason for reason in reasons),
                        reasons)

    def test_c_leg_carrying_evidence_invalid(self):
        evidence = self._evidence()
        cell = self._cell(evidence)
        entry = {"kind": "m1-pairs", "obs_a": "R", "obs_b": "C"}
        reasons = CLI.check_m_evidence(cell, self._leg(), entry,
                                       self._stage())
        self.assertTrue(any("m.json" in reason for reason in reasons),
                        reasons)

    def test_non_m_leg_without_evidence_ok(self):
        cell = self._cell(None)
        entry = {"kind": "m1-pairs", "obs_a": "R", "obs_b": "C"}
        self.assertEqual(
            CLI.check_m_evidence(cell, self._leg(), entry,
                                 self._stage()), [])


class FloorTests(unittest.TestCase):
    """G7: the 0.80 4K disabled-relative floor (ENVELOPE-only)."""

    def setUp(self):
        self.manifest = m1manifest.load_manifest(M1_MANIFEST)

    def _pair(self, name, ratio_t):
        first = "A" if int(name[3:]) % 2 == 0 else "B"
        order = ("A", "B") if first == "A" else ("B", "A")
        return {"pair": name, "valid": True, "reasons": [],
                "order": order,
                "ratios": {"throughput": ratio_t, "p99": 1.02}}

    def _judge(self, set_id, ratios):
        entry = CLI.find_set(self.manifest, set_id)
        pairs = [self._pair(f"leg{i:02d}", ratio)
                 for i, ratio in enumerate(ratios)]
        real_form = CLI.form_pairs
        try:
            CLI.form_pairs = lambda cells: pairs
            return CLI.judge_m1_set(
                set_id, entry, [{"cell": "fake", "errors": []}],
                self.manifest)
        finally:
            CLI.form_pairs = real_form

    def test_floor_holds(self):
        judged = self._judge("m1-P-4K-single-cd", [0.85] * 10)
        self.assertEqual(judged["verdict"], "ENVELOPE")
        self.assertTrue(judged["floor"]["holds"])
        self.assertEqual(judged["floor"]["threshold"], 0.80)

    def test_floor_breach(self):
        judged = self._judge("m1-P-4K-single-cd", [0.70] * 10)
        self.assertEqual(judged["verdict"], "ENVELOPE")
        self.assertFalse(judged["floor"]["holds"])

    def test_floor_needs_repeatability(self):
        # Median inside but only half the pairs inside: the floor
        # does not hold (same median+80% shape as the budgets).
        judged = self._judge("m1-P-4K-single-cd",
                             [0.85] * 5 + [0.70] * 5)
        self.assertFalse(judged["floor"]["holds"])

    def test_floor_only_4k_disabled_relative(self):
        judged = self._judge("m1-P-1M-single-cd", [0.99] * 10)
        self.assertNotIn("floor", judged)
        judged = self._judge("m1-P-4K-single-cr", [0.99] * 10)
        self.assertNotIn("floor", judged)


class UnknownFractionTests(unittest.TestCase):
    """G8: unknown-attribution fraction at report time."""

    def test_fraction_math(self):
        ctx = _ctx(3, 90, 100, 10, 10)
        self.assertAlmostEqual(m1validity.unknown_fraction(ctx),
                               0.10)

    def test_fraction_zero_system_none(self):
        self.assertIsNone(m1validity.unknown_fraction(
            _ctx(0, 0, 0, 0, 0)))
        self.assertIsNone(m1validity.unknown_fraction(
            _ctx(3, None, None, None, None)))

    def test_overlay_stashes_fraction(self):
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        ctx = _ctx(3, 90, 100, 10, 0)
        line = ("kryprobe: telemetry "
                + json.dumps({"v": 1, "ctx": ctx}) + "\n")
        (legs / "leg00B-capture.stderr.log").write_text(line)
        (legs / "leg00B-report.json").write_text(
            json.dumps(_api_report(100)))
        judged = {"leg_id": "leg00B", "valid": True,
                  "outcome": "valid", "reasons": [],
                  "driver": {"rc": 0}}
        leg = {"leg_id": "leg00B", "side": "B",
               "mode": "aggregation", "workload": "single"}
        entry = {"kind": "m1-pairs", "obs_a": "R", "obs_b": "C"}
        manifest = {"workloads": {"single": {"expected_rows": 3}}}
        out = CLI.apply_m1_ctx_overlay(tmp, judged, leg, entry,
                                       manifest)
        # unknown=10 on a below-cap shape is invalid, but the
        # fraction is still reported from sealed bytes.
        self.assertFalse(out["valid"])
        self.assertAlmostEqual(out["unknown_fraction"], 0.10)


class MActivityTests(unittest.TestCase):
    """G9: M-activity evidence without a product counter."""

    def test_progress_ticks_counted(self):
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        (legs / "leg00B-capture.stderr.log").write_text(
            "kryprobe: progress tick=1 rows=10 drops=0\n"
            "kryprobe: telemetry {\"v\":1,\"tick\":1}\n"
            "kryprobe: progress tick=2 rows=20 drops=0\n")
        self.assertEqual(
            CLI.count_progress_ticks(
                legs / "leg00B-capture.stderr.log"), 2)

    def test_progress_ticks_missing_log_none(self):
        self.assertIsNone(CLI.count_progress_ticks(
            Path("/nonexistent-capture.stderr.log")))

    def test_m_observer_metrics_carry_activity(self):
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        (legs / "leg00B-capture.stderr.log").write_text(
            "kryprobe: progress tick=1 rows=10 drops=0\n")
        (legs / "leg00B-report.workload-json").write_text(
            json.dumps(_wreport()))
        parsed = kparsers.parse_workload_report(
            legs / "leg00B-report.workload-json")
        leg = {"leg_id": "leg00B", "side": "B"}
        metrics = CLI.observer_metrics(tmp, leg, None, None,
                                       parsed_wl=parsed)
        self.assertEqual(metrics["progress_ticks"], 1)
        self.assertEqual(metrics["wl_metadata_status"], "available")
        self.assertIn("report_bytes", metrics)


class QuietMTests(unittest.TestCase):
    """G3/G4: M-set quiet legs run the M configuration."""

    def _cell(self, m_quiet=None, c_quiet=None):
        tmp = Path(tempfile.mkdtemp())
        if m_quiet is not None:
            (tmp / "quiet-report.workload-json").write_text(
                json.dumps(m_quiet))
        if c_quiet is not None:
            (tmp / "quiet-report.json").write_text(
                json.dumps(c_quiet))
        return tmp

    def test_m_quiet_clean(self):
        report = _wreport(system=0, perctx=0, calls=(),
                          status="unavailable",
                          reason="parse_failed",
                          metadata_cov="unavailable",
                          attribution="complete")
        cell = self._cell(m_quiet=report)
        judged = CLI.judge_m1_quiet(cell, "M")
        self.assertTrue(judged["valid"], judged["reasons"])

    def test_m_quiet_ambient_invalid(self):
        report = _wreport(system=7, perctx=7, calls=(7,))
        cell = self._cell(m_quiet=report)
        judged = CLI.judge_m1_quiet(cell, "M")
        self.assertFalse(judged["valid"])
        self.assertTrue(any("quiet" in reason
                            for reason in judged["reasons"]),
                        judged["reasons"])

    def test_m_quiet_missing_report_invalid(self):
        cell = self._cell()
        judged = CLI.judge_m1_quiet(cell, "M")
        self.assertFalse(judged["valid"])

    def test_c_quiet_unchanged(self):
        counters = [{"name": name, "value": 0}
                    for name in kparsers.LOSS_COUNTERS]
        report = {"observations": [{"backend_payload":
                                    {"row": "totals",
                                     "counts": {"calls": 0}}}],
                  "coverage": {"aggregate_counts":
                               {"counters": counters},
                               "detailed_events": {"counters": []}},
                  "verdict": {"status": "partial"}}
        cell = self._cell(c_quiet=report)
        judged = CLI.judge_m1_quiet(cell, "C")
        self.assertTrue(judged["valid"], judged["reasons"])

    def test_quiet_format_mixup_invalid(self):
        counters = [{"name": name, "value": 0}
                    for name in kparsers.LOSS_COUNTERS]
        c_report = {"observations": [{"backend_payload":
                                      {"row": "totals",
                                       "counts": {"calls": 0}}}],
                    "coverage": {"aggregate_counts":
                                 {"counters": counters},
                                 "detailed_events": {"counters": []}},
                    "verdict": {"status": "partial"}}
        m_report = _wreport(system=0, perctx=0, calls=(),
                            status="unavailable",
                            reason="parse_failed",
                            metadata_cov="unavailable")
        cell = self._cell(m_quiet=m_report, c_quiet=c_report)
        self.assertFalse(CLI.judge_m1_quiet(cell, "M")["valid"])
        self.assertFalse(CLI.judge_m1_quiet(cell, "C")["valid"])


class MetadataFileTests(unittest.TestCase):
    """M2: the campaign M-leg metadata file bytes."""

    def test_file_exists_and_validates(self):
        import jsonschema

        self.assertTrue(M1_METADATA.is_file())
        raw = M1_METADATA.read_bytes()
        doc = json.loads(raw)
        schema = json.loads(
            (ROOT / "schemas" /
             "workload-metadata-v1.schema.json").read_text())
        jsonschema.validate(doc, schema)

    def test_budgets(self):
        raw = M1_METADATA.read_bytes()
        doc = json.loads(raw)
        self.assertLessEqual(len(raw), 1048576)
        self.assertLessEqual(len(doc["entries"]), 1024)

    def test_no_cgroup_ids(self):
        # Bench cgroup IDs are runtime-assigned: a predeclared ID
        # could falsely resolve. Every campaign entry must carry
        # no cgroup key (parse path exercised, zero resolution).
        doc = json.loads(M1_METADATA.read_text())
        self.assertGreater(len(doc["entries"]), 0)
        for entry in doc["entries"]:
            self.assertIsNone(entry.get("cgroup_id"), entry)

    def test_kernel_identity_unknown(self):
        doc = json.loads(M1_METADATA.read_text())
        self.assertEqual(doc["kernel_identity"], "unknown")


class LabJourneyTests(unittest.TestCase):
    """G11: Docker-lab + A25 journey self-checks (oracles unrun)."""

    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, *argv], capture_output=True, text=True,
            timeout=60)

    def test_lab_help(self):
        proc = self._run(str(WORKLOAD_LAB / "docker_lab.py"),
                         "--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("two-workloads", proc.stdout)

    def test_lab_dry_run(self):
        proc = self._run(str(WORKLOAD_LAB / "docker_lab.py"),
                         "--dry-run", "two-workloads")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NOT_RUN", proc.stdout)

    def test_a25_help(self):
        proc = self._run(str(WORKLOAD_LAB / "a25.py"), "--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for journey in ("watch", "report", "policy", "replay",
                        "migration", "saturation",
                        "unavailable-metadata"):
            self.assertIn(journey, proc.stdout)

    def test_a25_dry_run(self):
        for journey in ("watch", "report", "policy", "replay",
                        "migration", "saturation",
                        "unavailable-metadata"):
            proc = self._run(str(WORKLOAD_LAB / "a25.py"),
                             "--dry-run", journey)
            self.assertEqual(proc.returncode, 0,
                             (journey, proc.stderr))
            self.assertIn("NOT_RUN", proc.stdout)

    def test_fixture_ledger_format(self):
        spec = importlib.util.spec_from_file_location(
            "workload_lab_common",
            str(WORKLOAD_LAB / "common.py"))
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        ledger = {"schema": "kryprobe-workload-lab-ledger/v1",
                  "workloads": [
                      {"name": "a", "cgroup_id": "123",
                       "ops": 100, "allocs": 1},
                      {"name": "b", "cgroup_id": "456",
                       "ops": 100, "allocs": 1}]}
        self.assertEqual(common.check_fixture_ledger(ledger), [])
        bad = dict(ledger, workloads=[])
        self.assertTrue(common.check_fixture_ledger(bad))

    def test_reconcile_oracle_math(self):
        spec = importlib.util.spec_from_file_location(
            "workload_lab_common",
            str(WORKLOAD_LAB / "common.py"))
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        # Flat-shape equation: per-cgroup enc+dec == 2 x ops.
        self.assertEqual(
            common.reconcile_cgroup(ops=100, enc=100, dec=100), [])
        self.assertTrue(
            common.reconcile_cgroup(ops=100, enc=100, dec=99))


class LabOracleTests(unittest.TestCase):
    """G11: pure oracle helpers (host-runnable halves)."""

    def _common(self):
        spec = importlib.util.spec_from_file_location(
            "workload_lab_common",
            str(WORKLOAD_LAB / "common.py"))
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        return common

    def _a25(self):
        import os

        sys.path.insert(0, str(WORKLOAD_LAB))
        os.environ.setdefault("WORKLOAD_LAB_IMPORT", "1")
        spec = importlib.util.spec_from_file_location(
            "workload_lab_a25", str(WORKLOAD_LAB / "a25.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_inventory_diff_clean(self):
        common = self._common()
        before = {"containers": ["db"], "networks": ["bridge"]}
        after = {"containers": ["db", "kryprobe-m1-05-a"],
                 "networks": ["bridge"]}
        self.assertEqual(common.diff_inventory(before, after), [])

    def test_inventory_diff_unrelated(self):
        common = self._common()
        before = {"containers": []}
        after = {"containers": ["someone-elses-db"]}
        self.assertTrue(common.diff_inventory(before, after))

    def test_proc_exited_self_alive(self):
        import os

        common = self._common()
        self.assertFalse(common.proc_exited(os.getpid()))
        self.assertTrue(common.proc_exited(2 ** 30))

    def test_offline_report_check_happy(self):
        a25 = self._a25()
        self.assertEqual(a25.check_workload_report(_wreport()), [])

    def test_offline_report_check_sad(self):
        a25 = self._a25()
        doc = _wreport()
        doc["ledger"]["per_context_sum"] = "7"
        self.assertTrue(a25.check_workload_report(doc))
        doc = _wreport()
        del doc["ledger"]
        self.assertTrue(a25.check_workload_report(doc))

    def test_exit_table(self):
        a25 = self._a25()
        self.assertEqual(a25.EXPECTED_EXITS["violation"], 10)
        self.assertEqual(a25.EXPECTED_EXITS["cannot-establish"], 3)
        self.assertEqual(a25.EXPECTED_EXITS["usage"], 2)


class VerifyCellMTests(unittest.TestCase):
    """G4/G6: verify_cell routes M sets end to end (quiet M,
    workload-json dispatch, M overlay, M evidence). Seal,
    receipts, and staged pins are stubbed (unit-covered
    elsewhere); everything downstream runs for real."""

    def _cell(self):
        from unittest import mock

        manifest = m1manifest.load_manifest(M1_MANIFEST)
        entry = CLI.find_set(manifest, "m1-P-4K-single-mr")
        tmp = Path(tempfile.mkdtemp())
        legs = tmp / "legs"
        legs.mkdir()
        meta_sha, helper_sha = "m" * 64, "h" * 64
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": "7.0.14",
                 "manifest_sha256": manifest["_manifest_sha256"],
                 "sha256": {
                     "obs-B/workload-metadata.json": meta_sha,
                     "obs-B/kryprobe-workload-helper": helper_sha}}
        (tmp / "stage.json").write_text(json.dumps(stage))
        legs_tsv = []
        for leg in CLI._gen_m1_legs(entry, manifest, 0,
                                       entry["pairs"]):
            legs_tsv.append("\t".join(str(leg[key]) for key in
                                      ("leg_id", "side", "mode",
                                       "cls", "driver", "size",
                                       "workload", "paced", "bulk",
                                       "threads")))
        (tmp / "legs.tsv").write_text("\n".join(legs_tsv) + "\n")
        quiet = _wreport(system=0, perctx=0, calls=(),
                         status="unavailable",
                         reason="parse_failed",
                         metadata_cov="unavailable")
        (tmp / "quiet-report.workload-json").write_text(
            json.dumps(quiet))
        summary = {"ops_total": 50, "ops_meas": 50,
                   "rows_meas": 100, "meas_window_s": 30,
                   "t_warm_start_ns": 0,
                   "t_meas_start_ns": 10_000_000_000,
                   "rc": 0, "fails": 0, "late": 0, "paced": 0,
                   "threads": 1}
        (legs / "leg00B-driver.csv.summary.json").write_text(
            json.dumps(summary))
        (legs / "leg00B-driver-rc.txt").write_text(
            "driver_rc=0\ndriver_timeout=0\n")
        rows = ["seq,phase,op,dt_ns"]
        for seq in range(50):
            rows.append(f"{seq},meas,encrypt,1000")
            rows.append(f"{seq},meas,decrypt,1000")
        (legs / "leg00B-driver.csv").write_text("\n".join(rows)
                                                + "\n")
        (legs / "leg00B-capture-rc.txt").write_text(
            "capture_rc=3\n")
        (legs / "leg00B-report.workload-json").write_text(
            json.dumps(_wreport()))
        (legs / "leg00B-capture.stderr.log").write_text(
            "kryprobe: telemetry "
            + json.dumps({"v": 1, "ctx": _ctx(3, 100, 100, 0, 0)})
            + "\n")
        (legs / "leg00B-m.json").write_text(json.dumps(
            {"schema": "kryprobe-m1-mleg/v1", "leg_id": "leg00B",
             "side": "B", "obs": "M",
             "metadata_sha256": meta_sha,
             "helper_sha256": helper_sha, "principal_uid": 1000}))
        patches = [
            mock.patch.object(CLI._CLI, "verify_cell_seal",
                              return_value=(True, {})),
            mock.patch.object(CLI, "check_run_receipts",
                              return_value=([], {})),
            mock.patch.object(CLI, "check_m1_stage_pins",
                              return_value=([], {}))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return tmp, manifest

    def test_m_set_routes_end_to_end(self):
        cell, manifest = self._cell()
        verdict = CLI.verify_cell(cell, manifest)
        self.assertEqual(verdict["errors"], [])
        self.assertTrue(verdict["quiet"]["valid"])
        by_id = {leg["leg_id"]: leg for leg in verdict["legs"]}
        self.assertEqual(len(by_id), 20)
        m_leg = by_id["leg00B"]
        self.assertTrue(m_leg["valid"], m_leg["reasons"])
        self.assertEqual(m_leg["observer"]["wl_metadata_status"],
                         "available")
        self.assertAlmostEqual(m_leg["unknown_fraction"], 0.0)
        # Siblings lack sealed files: invalid, never a crash.
        self.assertFalse(by_id["leg00A"]["valid"])

    def test_m_set_quiet_ambient_poison(self):
        cell, manifest = self._cell()
        (cell / "quiet-report.workload-json").write_text(
            json.dumps(_wreport(system=7, perctx=7, calls=(7,))))
        verdict = CLI.verify_cell(cell, manifest)
        self.assertTrue(verdict["spec_boot_invalid"])
        by_id = {leg["leg_id"]: leg for leg in verdict["legs"]}
        self.assertFalse(by_id["leg00B"]["valid"])


if __name__ == "__main__":
    unittest.main()
