#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for I06 independent archive/import verification (QUAL-01/QUAL-04).

Optional hardening only: the ordinary runner stays coherent (gen_legs
binding remains accepted, sealed M1 verdicts never change). Two
independent opt-in checks:

- QUAL-01: imported/resealed-cell spec binding — the sealed legs.tsv
  plus sealed stage roles/kernel must reconcile to the declared
  manifest entry (role/mode/workload/size/order), else the cell is
  refused under ``check_imported=True``.
- QUAL-04: judge dependency closure — the staged judge pins must
  cover the successor operand module and the manifest/parser
  dependencies; a missing/modified dependency refuses strict replay
  or is explicitly unbound.

Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_perf -p 'test_archive_verify.py'
"""

import hashlib
import importlib.util
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))

_SPEC = importlib.util.spec_from_file_location(
    "kcrypto_perf_cli",
    str(ROOT / "scripts" / "kcrypto-perf.py"))
CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CLI)

import test_judge as j  # noqa: E402


def _v3_manifest():
    return CLI.km1manifest.load_manifest(HERE / "cells-m1-v3.json")


def _v2_manifest():
    return CLI.km1manifest.load_manifest(HERE / "cells-m1.json")


def _cd_entry(manifest):
    return next(e for e in manifest["sets"]
                if e["obs_a"] == "D" and e["obs_b"] == "C"
                and e["workload"] == "single")


def _tsv_row(leg):
    return "\t".join(str(leg[key]) for key in
                      ("leg_id", "side", "mode", "cls", "driver",
                       "size", "workload", "paced", "bulk", "threads"))


def _sealed_m1_cell(tmp, manifest, entry, legs, obs_a="D", obs_b="C"):
    """Consistently sealed M1 cell for ``entry`` with the given TSV legs.

    Driver/quiet/receipt fixtures come from the frozen helper; the
    stage pins are rewritten to the M1 shape (like the QUAL-01 review
    reproduction) so ``verify_cell`` runs the real M1 path.
    """
    cell = j._sealed_cell(tmp, manifest_sha=manifest["_manifest_sha256"],
                          legs=len(legs))
    (cell / "legs.tsv").write_text(
        "\n".join(_tsv_row(leg) for leg in legs) + "\n")
    stage = json.loads((cell / "stage.json").read_text())
    stage.update(set=entry["id"], obs_a=obs_a, obs_b=obs_b)
    pins = {}
    for name in CLI.M1_BASE_PINS:
        if name == "kcrypto_fixture.ko":
            pins[name] = "none"
            continue
        path = cell / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("fixture\n")
        pins[name] = CLI.sha256_file(path)
    for name in ["obs-A/DISABLED"] + [f"obs-B/{n}" for n in CLI.M1_OBS_PINS]:
        path = cell / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n")
        pins[name] = CLI.sha256_file(path)
    stage["sha256"] = pins
    (cell / "stage.json").write_text(json.dumps(stage))
    (cell / "environment.txt").write_text(
        "driver=" + pins["kcrypto_perf.py"] + "\n" + "\n".join(
            key + "=" + pins["obs-B/" + tail] for key, tail in
            [("obs_b_kryprobe", "kryprobe"),
             ("obs_b_agg", "kryprobe-bpf/kcrypto.bpf.o"),
             ("obs_b_lc", "kryprobe-bpf/kcrypto-lifecycle.bpf.o")]) + "\n")
    names = [str(path.relative_to(cell)) for path in cell.rglob("*")
             if path.is_file() and path.name != "SHA256SUMS"]
    CLI.krecept.seal_artifacts(cell, names, writers_done=True)
    return cell


def _mutate(legs, leg_id, **fields):
    out = [dict(leg) for leg in legs]
    for leg in out:
        if leg["leg_id"] == leg_id:
            leg.update(fields)
    return out


class ImportedSpecTests(unittest.TestCase):
    """QUAL-01 unit binding: sealed spec vs declared manifest."""

    def test_generated_spec_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = CLI.gen_legs(entry, manifest, "set")
        self.assertEqual(CLI.check_imported_cell_spec(stage, spec, manifest),
                         [])

    def test_mode_mismatch_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = _mutate(CLI.gen_legs(entry, manifest, "set"),
                       "leg00B", mode="disabled")
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "mode flip must refuse binding")
        self.assertTrue(any("mode" in r for r in reasons), reasons)

    def test_workload_mismatch_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = _mutate(CLI.gen_legs(entry, manifest, "set"),
                       "leg00B", workload="churn_below", threads=200)
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "workload flip must refuse binding")
        self.assertTrue(any("workload" in r for r in reasons), reasons)

    def test_size_mismatch_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = _mutate(CLI.gen_legs(entry, manifest, "set"),
                       "leg00B", cls="P-64", size=64)
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "size flip must refuse binding")
        self.assertTrue(any("size" in r or "cls" in r for r in reasons),
                        reasons)

    def test_order_mismatch_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = CLI.gen_legs(entry, manifest, "set")
        spec[0], spec[1] = spec[1], spec[0]
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "order swap must refuse binding")
        self.assertTrue(any("order" in r for r in reasons), reasons)

    def test_role_mismatch_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "R"}
        spec = CLI.gen_legs(entry, manifest, "set")
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "role flip must refuse binding")
        self.assertTrue(any("obs_b" in r or "role" in r for r in reasons),
                        reasons)

    def test_kernel_mismatch_bound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": "6.12.111", "obs_a": "D", "obs_b": "C"}
        spec = CLI.gen_legs(entry, manifest, "set")
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "kernel flip must refuse binding")
        self.assertTrue(any("kernel" in r for r in reasons), reasons)

    def test_unknown_entry_unbound(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": "no-such-set",
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = CLI.gen_legs(entry, manifest, "set")
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "unknown set must not bind")
        self.assertTrue(any("unbound" in r for r in reasons), reasons)

    def test_diag_roles_bound(self):
        # P2-F1 positive control: staged D/C diag binds its manifest legs.
        manifest = _v3_manifest()
        entry = CLI.find_diag(manifest, "m1-diag-612-ctx")
        stage = {"kind": "diag", "diag": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spec = CLI.gen_legs(entry, manifest, "diag")
        self.assertEqual(CLI.check_imported_cell_spec(stage, spec, manifest),
                         [])

    def test_diag_role_mismatch_refused(self):
        # P2-F1: resealed D/R diagnostic must refuse the role boundary
        # (manifest diag carries no obs_*; staging pins implicit D/C).
        manifest = _v3_manifest()
        entry = CLI.find_diag(manifest, "m1-diag-612-ctx")
        stage = {"kind": "diag", "diag": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "R"}
        spec = CLI.gen_legs(entry, manifest, "diag")
        reasons = CLI.check_imported_cell_spec(stage, spec, manifest)
        self.assertTrue(reasons, "diag role flip must refuse binding")
        self.assertTrue(any("obs_b" in r or "role" in r for r in reasons),
                        reasons)

    def test_spare_window_bound(self):
        # P2-F2: runner spare legs (start_pair=10 within max_attempted)
        # bind field-exact against the 0..max_attempted-1 window.
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spares = CLI.gen_legs(entry, manifest, "set", 10, 2)
        self.assertEqual(CLI.check_imported_cell_spec(stage, spares,
                                                      manifest),
                         [])

    def test_spare_over_budget_refused(self):
        # P2-F2 guard: pair indices at/above max_attempted still refuse.
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        over = CLI.gen_legs(entry, manifest, "set",
                            entry["max_attempted"], 1)
        reasons = CLI.check_imported_cell_spec(stage, over, manifest)
        self.assertTrue(reasons, "over-budget legs must not bind")
        self.assertTrue(any("not declared" in r for r in reasons), reasons)

    def test_spare_field_flip_refused(self):
        # P2-F2 field-exact: a mode flip inside the spare window names
        # the field (not merely "not declared").
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spares = _mutate(CLI.gen_legs(entry, manifest, "set", 10, 2),
                         "leg10B", mode="disabled")
        reasons = CLI.check_imported_cell_spec(stage, spares, manifest)
        self.assertTrue(reasons, "spare mode flip must refuse")
        self.assertTrue(any("mode" in r for r in reasons), reasons)

    def test_spare_order_swap_refused(self):
        # P2-F2 order-aware: swapped spare legs refuse on order.
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        spares = CLI.gen_legs(entry, manifest, "set", 10, 2)
        spares[0], spares[1] = spares[1], spares[0]
        reasons = CLI.check_imported_cell_spec(stage, spares, manifest)
        self.assertTrue(reasons, "spare order swap must refuse")
        self.assertTrue(any("order" in r for r in reasons), reasons)


class ImportedVerifyTests(unittest.TestCase):
    """QUAL-01 end to end: mismatched sealed cells through verify_cell."""

    def _consistent(self, tmp):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        legs = CLI.gen_legs(entry, manifest, "set")
        return manifest, entry, _sealed_m1_cell(tmp, manifest, entry, legs)

    def _reseal(self, cell):
        names = [line.split("  ")[1]
                 for line in (cell / "SHA256SUMS").read_text().splitlines()]
        CLI.krecept.seal_artifacts(cell, names, writers_done=True)

    def _rewrite_tsv(self, cell, legs):
        (cell / "legs.tsv").write_text(
            "\n".join(_tsv_row(leg) for leg in legs) + "\n")
        stage = json.loads((cell / "stage.json").read_text())
        stage["sha256"]["legs.tsv"] = CLI.sha256_file(cell / "legs.tsv")
        (cell / "stage.json").write_text(json.dumps(stage))
        self._reseal(cell)

    def test_consistent_generated_cell_accepted(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest, _entry, cell = self._consistent(tmp)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got["seal_ok"])
        self.assertEqual(got.get("errors"), [], got.get("errors"))

    def test_resealed_mismatch_refused(self):
        # The review reproduction: disabled/disabled flat P64 TSV
        # resealed against a D/C P4K single manifest entry.
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest = _v3_manifest()
            entry = _cd_entry(manifest)
            legs = CLI.gen_legs(entry, manifest, "set")
            bad = [dict(leg, mode="disabled", cls="P-64",
                        driver="skcipher", size=64, workload="flat")
                   for leg in legs]
            cell = _sealed_m1_cell(tmp, manifest, entry, bad)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got["seal_ok"], "re-seal must hold")
        self.assertTrue(got.get("errors"), "mismatch must refuse")
        self.assertTrue(any("import" in e or "spec" in e
                            for e in got["errors"]), got["errors"])

    def test_mode_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest, entry, cell = self._consistent(tmp)
            legs = _mutate(CLI.gen_legs(entry, manifest, "set"),
                           "leg00B", mode="disabled")
            self._rewrite_tsv(cell, legs)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got.get("errors"), "mode flip must refuse")

    def test_role_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest, entry, cell = self._consistent(tmp)
            stage = json.loads((cell / "stage.json").read_text())
            stage["obs_b"] = "R"
            (cell / "stage.json").write_text(json.dumps(stage))
            self._reseal(cell)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got.get("errors"), "role flip must refuse")

    def test_workload_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest, entry, cell = self._consistent(tmp)
            legs = _mutate(CLI.gen_legs(entry, manifest, "set"),
                           "leg00B", workload="churn_below", threads=200)
            self._rewrite_tsv(cell, legs)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got.get("errors"), "workload flip must refuse")

    def test_size_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest, entry, cell = self._consistent(tmp)
            legs = _mutate(CLI.gen_legs(entry, manifest, "set"),
                           "leg00B", cls="P-64", size=64)
            self._rewrite_tsv(cell, legs)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got.get("errors"), "size flip must refuse")

    def test_order_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest, entry, cell = self._consistent(tmp)
            legs = CLI.gen_legs(entry, manifest, "set")
            legs[0], legs[1] = legs[1], legs[0]
            self._rewrite_tsv(cell, legs)
            got = CLI.verify_cell(cell, manifest, check_imported=True)
        self.assertTrue(got.get("errors"), "order swap must refuse")

    def test_default_verify_ignores_mismatch(self):
        # Opt-in only: ordinary verify_cell stays coherent.
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            manifest = _v3_manifest()
            entry = _cd_entry(manifest)
            legs = CLI.gen_legs(entry, manifest, "set")
            bad = [dict(leg, mode="disabled", cls="P-64",
                        driver="skcipher", size=64, workload="flat")
                   for leg in legs]
            cell = _sealed_m1_cell(tmp, manifest, entry, bad)
            got = CLI.verify_cell(cell, manifest)
        self.assertEqual(got.get("errors"), [])


class JudgeClosureTests(unittest.TestCase):
    """QUAL-04: staged judge pins cover the dependency closure."""

    def test_closure_covers_successor_and_loaders(self):
        self.assertIn("judge/successorvalidity.py", CLI.JUDGE_CLOSURE_PINS)
        self.assertIn("judge/parsers.py", CLI.JUDGE_CLOSURE_PINS)
        self.assertIn("judge/manifest.py", CLI.JUDGE_CLOSURE_PINS)
        self.assertIn("judge/m1manifest.py", CLI.JUDGE_CLOSURE_PINS)
        self.assertIn("judge/kcrypto-perf.py", CLI.JUDGE_CLOSURE_PINS)

    def test_closure_sources_exist(self):
        for src, _name in CLI.JUDGE_CLOSURE_SOURCES:
            self.assertTrue((CLI.HERE / src).is_file(), src)

    def _staging_args(self, tmp, obs_a="DISABLED", obs_b="CLI:BPF"):
        cli = Path(tmp) / "cli"
        bpf = Path(tmp) / "bpf"
        cli.write_bytes(b"fake-kryprobe")
        bpf.mkdir()
        (bpf / "kcrypto.bpf.o").write_bytes(b"fake-obj-agg")
        (bpf / "kcrypto-lifecycle.bpf.o").write_bytes(b"fake-obj-lc")
        return SimpleNamespace(
            out_root=str(Path(tmp) / "out"),
            obs_a=obs_a,
            obs_b=f"{cli}:{bpf}" if obs_b == "CLI:BPF" else obs_b,
            metadata=None,
            driver=str(ROOT / "tests" / "fixtures" / "kcrypto_perf_m1.py"))

    def test_staging_writes_closure(self):
        manifest = _v3_manifest()
        entry = _cd_entry(manifest)
        legs = CLI.gen_legs(entry, manifest, "set")
        vng = manifest["global"]["vng"][entry["kernel"]]
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            home = Path(tmp) / "home"
            cfg = home / ".cache" / "virtme-ng" / vng / "amd64" / "boot"
            cfg.mkdir(parents=True)
            (cfg / "config-guest").write_text("fake-guest-config\n")
            import os
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                args = self._staging_args(tmp)
                run_dir, stage, _timeout = CLI.stage_m1_run_dir(
                    args, entry, manifest, "set",
                    manifest["_manifest_sha256"], vng, legs, entry["id"])
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            for name in CLI.JUDGE_CLOSURE_PINS:
                self.assertIn(name, stage["sha256"], name)
                target = run_dir / name
                self.assertTrue(target.is_file(), name)
                self.assertEqual(CLI.sha256_file(target),
                                 stage["sha256"][name], name)

    def _closure_cell(self, tmp):
        cell = Path(tmp) / "cell"
        (cell / "judge").mkdir(parents=True)
        pins = {}
        for src, name in CLI.JUDGE_CLOSURE_SOURCES:
            blob = (CLI.HERE / src).read_bytes()
            (cell / "judge" / name).write_bytes(blob)
            pins[f"judge/{name}"] = hashlib.sha256(blob).hexdigest()
        return cell, {"sha256": pins}

    def test_matching_closure_accepted(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            cell, stage = self._closure_cell(tmp)
            reasons, observed = CLI.check_judge_closure(cell, stage)
        self.assertEqual(reasons, [])
        self.assertEqual(set(observed["checked"]), set(CLI.JUDGE_CLOSURE_PINS))

    def test_modified_dependency_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            cell, stage = self._closure_cell(tmp)
            (cell / "judge" / "successorvalidity.py").write_text(
                "# tampered\n")
            reasons, _observed = CLI.check_judge_closure(cell, stage)
        self.assertTrue(reasons, "modified dep must refuse")
        self.assertTrue(any("successorvalidity" in r for r in reasons),
                        reasons)

    def test_missing_dependency_refused(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            cell, stage = self._closure_cell(tmp)
            (cell / "judge" / "parsers.py").unlink()
            reasons, _observed = CLI.check_judge_closure(cell, stage)
        self.assertTrue(reasons, "missing dep must refuse")
        self.assertTrue(any("parsers" in r for r in reasons), reasons)

    def test_legacy_cell_explicitly_unbound(self):
        reasons, observed = CLI.check_judge_closure(
            Path("/nonexistent"), {"sha256": {}})
        self.assertTrue(reasons, "absent closure must not bind")
        self.assertTrue(any("unbound" in r for r in reasons), reasons)
        self.assertIn("judge/successorvalidity.py",
                      observed.get("unbound", []))

    def test_strict_verify_cell_closure(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            cell = j._sealed_cell(tmp, manifest_sha="MANIFEST")
            stage = json.loads((cell / "stage.json").read_text())
            for src, name in CLI.JUDGE_CLOSURE_SOURCES:
                blob = (CLI.HERE / src).read_bytes()
                (cell / "judge").mkdir(exist_ok=True)
                (cell / "judge" / name).write_bytes(blob)
                stage["sha256"][f"judge/{name}"] = hashlib.sha256(
                    blob).hexdigest()
            (cell / "stage.json").write_text(json.dumps(stage))
            names = [line.split("  ")[1] for line in
                     (cell / "SHA256SUMS").read_text().splitlines()]
            names += [f"judge/{name}" for _src, name in
                      CLI.JUDGE_CLOSURE_SOURCES]
            CLI.krecept.seal_artifacts(cell, names, writers_done=True)
            manifest = {"_manifest_sha256": "MANIFEST",
                        "global": {"warmup_s": 10.0, "measure_s": 30.0}}
            got = CLI.verify_cell(cell, manifest, require_judge_closure=True)
            self.assertEqual(got.get("errors"), [], got.get("errors"))
            (cell / "judge" / "successorvalidity.py").write_text(
                "# tampered\n")
            CLI.krecept.seal_artifacts(cell, names, writers_done=True)
            got = CLI.verify_cell(cell, manifest, require_judge_closure=True)
            self.assertTrue(got.get("errors"), "tampered dep must refuse")
            got = CLI.verify_cell(cell, manifest)
            self.assertTrue(
                got.get("errors"),
                "pin gate still catches sealed-byte mismatch by default")

    def test_offline_reconstruction_from_sealed_bytes(self):
        # Replay uses only the sealed judge bytes + stage pins: copy
        # the judge dir aside (originating checkout "unavailable"),
        # re-hash, and compare against the sealed stage pins.
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            cell, stage = self._closure_cell(tmp)
            replay = Path(tmp) / "replay"
            import shutil
            shutil.copytree(cell / "judge", replay / "judge")
            pins = stage["sha256"]
            for name, pinned in sorted(pins.items()):
                actual = CLI.sha256_file(replay / name)
                self.assertEqual(actual, pinned, name)
            (replay / "judge" / "m1manifest.py").write_text("# tampered\n")
            tampered = CLI.sha256_file(replay / "judge" / "m1manifest.py")
            self.assertNotEqual(tampered, pins["judge/m1manifest.py"])
            reasons, _observed = CLI.check_judge_closure(replay, stage)
            self.assertTrue(reasons, "tampered replay must refuse")


class FrozenV2CompatTests(unittest.TestCase):
    """I06 changes nothing for frozen/v2 verdicts by default."""

    def test_frozen_cell_default_verdict_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="t14i06") as tmp:
            cell = j._sealed_cell(tmp)
            manifest = {"_manifest_sha256": "MANIFEST",
                        "global": {"warmup_s": 10.0, "measure_s": 30.0}}
            got = CLI.verify_cell(cell, manifest)
        self.assertEqual(got.get("errors"), [])
        self.assertTrue(all(leg["valid"] for leg in got["legs"]))

    def test_new_flags_default_off(self):
        params = inspect.signature(CLI.verify_cell).parameters
        self.assertIs(params["check_imported"].default, False)
        self.assertIs(params["require_judge_closure"].default, False)

    def test_v2_epoch_never_successor(self):
        manifest = _v2_manifest()
        self.assertEqual(manifest["manifest_version"], 2)
        entry = _cd_entry(manifest)
        legs = CLI.gen_legs(entry, manifest, "set")
        self.assertFalse(CLI._successor_leg(manifest, legs[1], entry))
        stage = {"kind": "set", "set": entry["id"],
                 "kernel": entry["kernel"], "obs_a": "D", "obs_b": "C"}
        self.assertEqual(CLI.check_imported_cell_spec(stage, legs, manifest),
                         [])


if __name__ == "__main__":
    unittest.main()
