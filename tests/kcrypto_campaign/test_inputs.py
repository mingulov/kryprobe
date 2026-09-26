#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the P2 campaign input loader + receipt verifier.

Standard library only; no guests, no privilege. Run from this
directory::

    python3 -B -m unittest -v test_inputs
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import inputs
import receipt

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "pressure.json"


def write_manifest(tmp: Path, obj) -> Path:
    path = tmp / "pressure.json"
    if isinstance(obj, str):
        path.write_text(obj)
    else:
        path.write_text(json.dumps(obj))
    return path


def base_manifest() -> dict:
    return json.loads(MANIFEST.read_bytes())


class LoaderTests(unittest.TestCase):
    def test_frozen_manifest_loads(self):
        manifest = inputs.load_inputs(MANIFEST)
        self.assertEqual(manifest["$schema"], inputs.SCHEMA)
        self.assertEqual(len(manifest["cells"]), 8)
        self.assertEqual(
            manifest["_manifest_sha256"], inputs.manifest_sha256(MANIFEST)
        )

    def test_p2_runnable_set(self):
        runnable = {
            cell["id"]: cell["portions"]
            for cell in inputs.p2_cells(inputs.load_inputs(MANIFEST))
        }
        self.assertEqual(
            runnable,
            {
                "E01": ["E01a"],
                "E02": ["E02-totals"],
                "E03": ["E03-totals"],
                "E05": ["E05-sync"],
                "E06": ["E06-cap"],
                "E07": ["E07-overload"],
            },
        )

    def test_mutated_limits_change_freeze_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            mutated = base_manifest()
            mutated["cells"][5]["stimulus"]["planned_completions"] = 100006
            path = write_manifest(Path(tmp), mutated)
            self.assertNotEqual(
                inputs.manifest_sha256(path), inputs.manifest_sha256(MANIFEST)
            )

    def test_unknown_schema_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["$schema"] = "kryprobe-pressure-campaign/v2"
            with self.assertRaisesRegex(inputs.InputError, "unknown manifest schema"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_version_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["manifest_version"] = 2
            with self.assertRaisesRegex(inputs.InputError, "unknown manifest_version"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_missing_top_key_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            del bad["freeze_rule"]
            with self.assertRaisesRegex(inputs.InputError, "missing required keys"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_duplicate_cell_id_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"].append(copy.deepcopy(bad["cells"][0]))
            with self.assertRaisesRegex(inputs.InputError, "duplicate cell id"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_cell_status_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["status"] = "MAYBE"
            with self.assertRaisesRegex(inputs.InputError, "unknown status"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_portion_status_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"][0]["status"] = "P6"
            with self.assertRaisesRegex(inputs.InputError, "unknown status"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_cells_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"] = []
            with self.assertRaisesRegex(inputs.InputError, "non-empty list"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_non_json_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(inputs.InputError, "not valid JSON"):
                inputs.load_inputs(write_manifest(Path(tmp), "{nope"))

    def test_bool_manifest_version_refuses(self):
        # P2r/C7: True == 1 in Python, so a bare != check accepts the
        # bool. The loader must demand a genuine int.
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["manifest_version"] = True
            with self.assertRaisesRegex(inputs.InputError, "manifest_version"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_duplicate_portion_id_refuses(self):
        # P2r/C7: portion IDs must be unique within their cell.
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"].append(
                copy.deepcopy(bad["cells"][0]["portions"][0])
            )
            with self.assertRaisesRegex(inputs.InputError, "duplicate portion id"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_stimulus_refuses(self):
        # P2r/C7: stimulus/oracle/bounds must be nonempty mappings.
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["stimulus"] = {}
            with self.assertRaisesRegex(inputs.InputError, "nonempty mapping"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_oracle_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][1]["oracle"] = {}
            with self.assertRaisesRegex(inputs.InputError, "nonempty mapping"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_bounds_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][2]["bounds"] = {}
            with self.assertRaisesRegex(inputs.InputError, "nonempty mapping"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_non_mapping_stimulus_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["stimulus"] = ["burst"]
            with self.assertRaisesRegex(inputs.InputError, "nonempty mapping"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_global_refuses(self):
        # P2r/C7: the shared limits table must be a nonempty mapping.
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["global"] = {}
            with self.assertRaisesRegex(inputs.InputError, "global"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_non_mapping_global_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["global"] = ["profile"]
            with self.assertRaisesRegex(inputs.InputError, "global"):
                inputs.load_inputs(write_manifest(Path(tmp), bad))


def passing_receipt() -> dict:
    return {
        "process": {"exit": 0, "timed_out": False, "reaped": True},
        "cleanup": {"remaining_owned": {}, "preexisting_unchanged": True},
        "custody": {"hashes_unchanged": True},
        "observation": {"expected": {"ops": 1000}, "actual": {"ops": 1000}},
    }


class VerifierTests(unittest.TestCase):
    def test_clean_run_passes(self):
        verdict = receipt.verify(passing_receipt())
        self.assertEqual(verdict, {"verdict": "PASS", "reasons": []})

    def test_timeout_cannot_pass(self):
        rec = passing_receipt()
        rec["process"]["timed_out"] = True
        verdict = receipt.verify(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("timed out" in r for r in verdict["reasons"]))

    def test_nonzero_exit_cannot_pass(self):
        rec = passing_receipt()
        rec["process"]["exit"] = 1
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")

    def test_unreaped_worker_cannot_pass(self):
        rec = passing_receipt()
        rec["process"]["reaped"] = False
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")

    def test_remaining_owned_resources_cannot_pass(self):
        rec = passing_receipt()
        rec["cleanup"]["remaining_owned"] = {"1234": {"args": ["qemu-system-x86_64"]}}
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")

    def test_changed_preexisting_resources_cannot_pass(self):
        rec = passing_receipt()
        rec["cleanup"]["preexisting_unchanged"] = False
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")

    def test_changed_hashes_cannot_pass(self):
        rec = passing_receipt()
        rec["custody"]["hashes_unchanged"] = False
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")

    def test_count_mismatch_cannot_pass(self):
        rec = passing_receipt()
        rec["observation"]["actual"] = {"ops": 999}
        verdict = receipt.verify(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("expected" in r for r in verdict["reasons"]))

    def test_omitted_loss_dimensions_cannot_pass(self):
        rec = passing_receipt()
        rec["observation"]["omitted_loss_dimensions"] = ["ring"]
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")

    def test_not_run_needs_reason_and_control(self):
        rec = {"verdict": "NOT_RUN"}
        self.assertEqual(receipt.verify(rec)["verdict"], "FAIL")
        rec = {"verdict": "NOT_RUN", "reason": "P6 gate open", "positive_control": "E01a"}
        self.assertEqual(receipt.verify(rec)["verdict"], "NOT_RUN")

    def test_false_oracle_check_cannot_pass(self):
        # P2r/C4: the reviewers' E01a-shaped counterexample — counts
        # equal, but the zero-loss gate failed (ring_drops=1). The old
        # verifier ignored `checks` and returned PASS.
        rec = passing_receipt()
        rec["checks"] = {"ledger_exact": True, "zero_ring_drops": False}
        verdict = receipt.verify(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(
            any("zero_ring_drops" in r for r in verdict["reasons"]),
            verdict["reasons"],
        )

    def test_nonempty_oracle_failed_cannot_pass(self):
        # P2r/C4: a named failed oracle always fails the receipt, even
        # when every other gate holds.
        rec = passing_receipt()
        rec["checks"] = {"zero_ring_drops": False}
        rec["oracle_failed"] = ["zero_ring_drops"]
        verdict = receipt.verify(rec)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(
            any("zero_ring_drops" in r for r in verdict["reasons"]),
            verdict["reasons"],
        )

    def test_empty_oracle_failed_with_true_checks_passes(self):
        # An explicitly empty failure list alongside all-true checks is
        # the honest pass shape — it must stay green.
        rec = passing_receipt()
        rec["checks"] = {"ledger_exact": True, "zero_ring_drops": True}
        rec["oracle_failed"] = []
        self.assertEqual(receipt.verify(rec)["verdict"], "PASS")


class SealTests(unittest.TestCase):
    def test_seal_refuses_open_writers(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "writers_done"):
                receipt.seal_artifacts(Path(tmp), [], writers_done=False)

    def test_seal_hashes_and_writes_sums(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "out.json").write_text("{}\n")
            sums = receipt.seal_artifacts(run, ["out.json"], writers_done=True)
            self.assertEqual(sums, {"out.json": receipt.sha256_file(run / "out.json")})
            self.assertIn("out.json", (run / "SHA256SUMS").read_text())

    def test_atomic_write_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            receipt.atomic_write_json(target, {"b": 1, "a": [1, 2]})
            self.assertEqual(json.loads(target.read_text()), {"a": [1, 2], "b": 1})
            self.assertFalse((Path(tmp) / "r.json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
