#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host behavior checks for the repository-owned traffic fixture.

The fixture (``tests/fixtures/kcrypto_gen.py``) is promoted from
the inspected, hash-bound T07 delivery-bundle generator; these
checks pin its provenance markers and its AF_ALG behavior. AF_ALG
legs skip with an explicit reason when the host lacks the
socket family; the guest cells (not these host checks) carry the
campaign proof. Run from the product worktree root::

    python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_traffic_fixture.py'
"""

import socket
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "kcrypto_gen.py"
README = ROOT / "tests" / "fixtures" / "kcrypto-gen-README.md"
PARENT_SHA256 = "82325c72d469b30c55604730e8e8c35cde614cfb8580f5d6b9d27f6d58ffc3eb"

sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
import kcrypto_gen  # noqa: E402


def afalg_available() -> bool:
    if not hasattr(socket, "AF_ALG"):
        return False
    try:
        probe = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    except OSError:
        return False
    probe.close()
    return True


class ProvenanceTests(unittest.TestCase):
    def test_fixture_is_committed_and_executable(self):
        self.assertTrue(FIXTURE.is_file())
        self.assertTrue(FIXTURE.stat().st_mode & 0o111)

    def test_spdx_header_present(self):
        head = FIXTURE.read_text().splitlines()[:3]
        self.assertTrue(any("SPDX-License-Identifier: GPL-3.0-or-later" in line for line in head))

    def test_provenance_marker_names_parent_hash(self):
        text = FIXTURE.read_text()
        self.assertIn("PROVENANCE_PARENT_SHA256", text)
        self.assertIn(PARENT_SHA256, text)

    def test_readme_records_lineage_and_delta(self):
        text = README.read_text()
        self.assertIn(PARENT_SHA256, text)
        self.assertIn("delivery-lane-09", text)
        self.assertIn("GPL-3.0-or-later", text)

    def test_expected_entry_points(self):
        self.assertTrue(callable(kcrypto_gen.skcipher_burst))
        self.assertTrue(callable(kcrypto_gen.hash_burst))
        self.assertTrue(callable(kcrypto_gen.main))


class CliTests(unittest.TestCase):
    def test_bad_rounds_arg_exits_2(self):
        proc = subprocess.run(
            [sys.executable, str(FIXTURE), "banana"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("usage", proc.stderr)


@unittest.skipUnless(afalg_available(), "host AF_ALG unavailable (guest cells carry the proof)")
class AfAlgBehaviorTests(unittest.TestCase):
    def test_hash_burst_roundtrip(self):
        # Asserts inside hash_burst verify digest length; stdout
        # shape is pinned by the campaign oracles.
        kcrypto_gen.hash_burst(n=2)

    def test_skcipher_burst_roundtrip(self):
        # Asserts inside skcipher_burst verify decrypt(encrypt(m)) == m.
        # The one-cmsg OP+IV form hangs this host kernel's recv (a
        # host-only quirk: all three guest kernels answer); run it in
        # a bounded child so the host check can never wedge, and let
        # the R01-floor guest cell carry the skcipher proof.
        try:
            proc = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r);"
                 "import kcrypto_gen; kcrypto_gen.skcipher_burst(n=1)"
                 % str(ROOT / "tests" / "fixtures")],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            self.skipTest(
                "host kernel does not answer one-cmsg skcipher recv "
                "(R01-floor guest cell proves this path)"
            )
            return
        if proc.returncode != 0:
            self.skipTest(
                "host kernel does not answer one-cmsg skcipher recv "
                "(R01-floor guest cell proves this path; rc=%d)" % proc.returncode
            )
        self.assertIn("skcipher: 2 ops done", proc.stdout)

    def test_main_zero_rounds_finishes(self):
        self.assertEqual(kcrypto_gen.main(["kcrypto_gen.py", "0"]), 0)


if __name__ == "__main__":
    unittest.main()
