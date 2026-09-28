#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for the P8/T13 consumer-campaign input loader.

Standard library only; no guests, no privilege. Run from the
product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_consumer_inputs.py'

The loader lives in ``scripts/kcrypto_campaign/`` (the P8 common
campaign harness); this file only imports it as a package.
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_campaign import inputs as cinputs  # noqa: E402

MANIFEST = HERE / "cells.json"


def write_manifest(tmp: Path, obj) -> Path:
    path = tmp / "cells.json"
    if isinstance(obj, str):
        path.write_text(obj)
    else:
        path.write_text(json.dumps(obj))
    return path


def base_manifest() -> dict:
    return json.loads(MANIFEST.read_bytes())


class ConsumerLoaderTests(unittest.TestCase):
    def test_frozen_manifest_loads(self):
        manifest = cinputs.load_inputs(MANIFEST)
        self.assertEqual(manifest["$schema"], cinputs.SCHEMA)
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual(
            manifest["_manifest_sha256"], cinputs.manifest_sha256(MANIFEST)
        )
        self.assertTrue(len(manifest["cells"]) >= 6)

    def test_t13_runnable_set(self):
        runnable = {
            cell["id"]: sorted(p["id"] for p in cell["portions"])
            for cell in cinputs.t13_cells(cinputs.load_inputs(MANIFEST))
        }
        self.assertEqual(
            runnable,
            {
                "R01-det": ["R01-det-7014", "R01-det-726"],
                "R01-floor": ["R01-floor-612"],
                "R02-dmcrypt": ["R02-7014", "R02-726"],
                "R03-xfrm": ["R03-7014", "R03-726"],
                "R04-deny": ["R04-deny-7014", "R04-deny-726"],
                "R04-foreign": ["R04-foreign-7014", "R04-foreign-726"],
            },
        )

    def test_portion_kernels_and_profiles_pinned(self):
        manifest = cinputs.load_inputs(MANIFEST)
        seen = {}
        for cell in manifest["cells"]:
            for portion in cell["portions"]:
                seen[portion["id"]] = (portion["kernel"], portion["profile"])
        self.assertEqual(seen["R01-floor-612"], ("6.12.111", "api-returns"))
        self.assertEqual(seen["R02-7014"], ("7.0.14", "api-returns"))
        self.assertEqual(seen["R03-726"], ("7.2.6", "api-returns"))

    def test_mutated_limits_change_freeze_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            mutated = base_manifest()
            first = mutated["cells"][0]["portions"][0]
            first["bounds"]["timeout_s"] = first["bounds"]["timeout_s"] + 1
            path = write_manifest(Path(tmp), mutated)
            self.assertNotEqual(
                cinputs.manifest_sha256(path), cinputs.manifest_sha256(MANIFEST)
            )

    def test_unknown_schema_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["$schema"] = "kryprobe-consumer-campaign/v2"
            with self.assertRaisesRegex(cinputs.InputError, "unknown manifest schema"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_pressure_schema_refuses(self):
        # The P2 pressure manifest is a different schema; the
        # consumer loader must not silently accept it.
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["$schema"] = "kryprobe-pressure-campaign/v1"
            with self.assertRaisesRegex(cinputs.InputError, "unknown manifest schema"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_version_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["manifest_version"] = 2
            with self.assertRaisesRegex(cinputs.InputError, "unknown manifest_version"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_bool_manifest_version_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["manifest_version"] = True
            with self.assertRaisesRegex(cinputs.InputError, "manifest_version"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_missing_top_key_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            del bad["freeze_rule"]
            with self.assertRaisesRegex(cinputs.InputError, "missing required keys"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_duplicate_cell_id_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"].append(copy.deepcopy(bad["cells"][0]))
            with self.assertRaisesRegex(cinputs.InputError, "duplicate cell id"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_duplicate_portion_id_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            cell = bad["cells"][0]
            cell["portions"].append(copy.deepcopy(cell["portions"][0]))
            with self.assertRaisesRegex(cinputs.InputError, "duplicate portion id"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_cell_status_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["status"] = "P2"
            with self.assertRaisesRegex(cinputs.InputError, "unknown status"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_portion_status_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"][0]["status"] = "P8"
            with self.assertRaisesRegex(cinputs.InputError, "unknown status"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_kernel_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"][0]["kernel"] = "7.9.9"
            with self.assertRaisesRegex(cinputs.InputError, "unknown kernel"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_unknown_profile_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"][0]["profile"] = "request-lifecycle-v2"
            with self.assertRaisesRegex(cinputs.InputError, "unknown profile"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_missing_portion_key_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            del bad["cells"][0]["portions"][0]["oracle"]
            with self.assertRaisesRegex(cinputs.InputError, "missing required keys"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_portion_stimulus_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"][0]["stimulus"] = {}
            with self.assertRaisesRegex(cinputs.InputError, "nonempty mapping"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_portion_oracle_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][1]["portions"][0]["oracle"] = {}
            with self.assertRaisesRegex(cinputs.InputError, "nonempty mapping"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_portion_bounds_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][2]["portions"][0]["bounds"] = {}
            with self.assertRaisesRegex(cinputs.InputError, "nonempty mapping"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_non_mapping_bounds_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"][0]["bounds"] = ["timeout"]
            with self.assertRaisesRegex(cinputs.InputError, "nonempty mapping"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_global_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["global"] = {}
            with self.assertRaisesRegex(cinputs.InputError, "global"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_cells_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"] = []
            with self.assertRaisesRegex(cinputs.InputError, "non-empty list"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_empty_portions_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = base_manifest()
            bad["cells"][0]["portions"] = []
            with self.assertRaisesRegex(cinputs.InputError, "non-empty list"):
                cinputs.load_inputs(write_manifest(Path(tmp), bad))

    def test_non_json_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(cinputs.InputError, "not valid JSON"):
                cinputs.load_inputs(write_manifest(Path(tmp), "{nope"))


if __name__ == "__main__":
    unittest.main()
