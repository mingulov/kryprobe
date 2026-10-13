#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""F09 release-gate regression tests: exact-SHA CI verifier, trusted-checkout
wiring, and the explicit v0.1.0-only scope refusal (QUAL-03/QUAL-05).

Stdlib only. Run from the product worktree root::

    python3 -B -m unittest discover -s tests/release -p 'test_verify_ci.py' -v
"""

import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

_SPEC = importlib.util.spec_from_file_location(
    "release_verify_ci",
    str(ROOT / "packaging" / "release" / "verify-ci.py"))
VERIFY_CI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(VERIFY_CI)

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "ffffffffffffffffffffffffffffffffffffffff"


def job(name, conclusion="success"):
    return {"name": name, "conclusion": conclusion}


def run_doc(head_sha=SHA, status="completed", conclusion="success"):
    return {"headSha": head_sha, "status": status, "conclusion": conclusion}


def four_green():
    return [job("host gate"), job("BPF lane (unprivileged)"),
            job("privileged sudo lane"), job("supply chain")]


def v010_green():
    """v0.1.0 tag tree lanes (the only supported release): 3 jobs."""
    return [job("host gate"), job("BPF lane (unprivileged)"),
            job("supply chain")]


class ValidateRequiredJobsTest(unittest.TestCase):
    """Pure verifier fixtures (QUAL-03)."""

    def test_four_green_accepts(self):
        self.assertEqual(
            VERIFY_CI.validate_required_jobs(SHA, run_doc(), four_green()), [])

    def test_v010_three_green_accepts(self):
        """P1 oracle: the supported v0.1.0 tag tree runs exactly 3 lanes;
        an all-green 3-lane run on the tag peel must ACCEPT."""
        self.assertEqual(
            VERIFY_CI.validate_required_jobs(SHA, run_doc(), v010_green()), [])

    def test_three_green_missing_required_refuses(self):
        jobs = [j for j in four_green() if j["name"] != "supply chain"]
        reasons = VERIFY_CI.validate_required_jobs(SHA, run_doc(), jobs)
        self.assertTrue(reasons)
        self.assertTrue(any("supply chain" in r for r in reasons))

    def test_required_not_successful_refuses(self):
        for conclusion in ("failure", "cancelled", "skipped", None):
            with self.subTest(conclusion=conclusion):
                jobs = four_green()
                jobs[0] = job("host gate", conclusion)
                reasons = VERIFY_CI.validate_required_jobs(
                    SHA, run_doc(), jobs)
                self.assertTrue(reasons)
                self.assertTrue(any("host gate" in r for r in reasons))

    def test_duplicate_required_refuses(self):
        jobs = four_green() + [job("host gate")]
        reasons = VERIFY_CI.validate_required_jobs(SHA, run_doc(), jobs)
        self.assertTrue(reasons)
        self.assertTrue(any("duplicate" in r for r in reasons))

    def test_wrong_sha_refuses(self):
        reasons = VERIFY_CI.validate_required_jobs(
            SHA, run_doc(head_sha=OTHER_SHA), four_green())
        self.assertTrue(reasons)

    def test_extra_unrelated_green_accepts(self):
        jobs = four_green() + [job("nightly docs check")]
        self.assertEqual(
            VERIFY_CI.validate_required_jobs(SHA, run_doc(), jobs), [])

    def test_incomplete_run_refuses(self):
        reasons = VERIFY_CI.validate_required_jobs(
            SHA, run_doc(status="in_progress", conclusion=None), four_green())
        self.assertTrue(reasons)

    def test_legacy_three_success_string_rejects_four_green(self):
        """QUAL-03 regression oracle: the old fixed-count gate refused the
        current all-green four-job CI. The new verifier must accept it."""
        jobs = four_green()
        legacy = ",".join(sorted(j["conclusion"] for j in jobs))
        self.assertNotEqual(legacy, "success,success,success")
        self.assertEqual(
            VERIFY_CI.validate_required_jobs(SHA, run_doc(), jobs), [])

    def test_required_set_matches_supported_tag_ci_yml(self):
        """P1: the verifier's expected set is exactly the display names emitted
        by the SUPPORTED TAG tree ci.yml (v0.1.0), not the current tree.
        The gate evaluates tag-tree runs; the current tree carries a 4th
        privileged lane that no v0.1.0-peel run can contain."""
        tag_ci = subprocess.check_output(
            ["git", "show", "v0.1.0^{}:.github/workflows/ci.yml"],
            cwd=ROOT, text=True, timeout=60)
        names = re.findall(r"^    name: (.+)$", tag_ci, re.M)
        self.assertEqual(sorted(names), sorted(VERIFY_CI.REQUIRED_JOBS))


def require_green_section(release_yml):
    start = release_yml.index("  require-green:")
    end = release_yml.index("\n  publish:")
    return release_yml[start:end]


class ReleaseWorkflowWiringTest(unittest.TestCase):
    """Static release.yml wiring: trusted checkout + verifier (QUAL-03)."""

    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        cls.require_green = require_green_section(cls.text)

    def test_no_legacy_three_success_gate(self):
        self.assertNotIn("success,success,success", self.text)

    def test_top_level_permissions_empty(self):
        self.assertIsNotNone(
            re.search(r"^permissions: \{\}\s*$", self.text, re.M))

    def test_require_green_least_privilege(self):
        perms = re.search(r"    permissions:\n((?:      .*\n)+)",
                          self.require_green)
        self.assertIsNotNone(perms)
        lines = sorted(line.strip() for line in
                       perms.group(1).strip().splitlines())
        self.assertEqual(lines, ["actions: read", "contents: read"])

    def test_pinned_checkout_precedes_verifier(self):
        checkout = None
        for match in re.finditer(
                r"uses: actions/checkout@([0-9a-f]{40})", self.require_green):
            checkout = match.start()
        self.assertIsNotNone(checkout, "no pinned checkout in require-green")
        invoke = self.require_green.index("verify-ci.py")
        self.assertLess(checkout, invoke)
        self.assertIn("tooling_sha", self.require_green)

    def test_verifier_bound_to_tag_peel(self):
        self.assertIn("steps.resolve.outputs.peel", self.require_green)
        invoke_line = next(
            line for line in self.require_green.splitlines()
            if "verify-ci.py" in line)
        self.assertIn("steps.resolve.outputs.peel",
                      self.require_green[max(0, self.require_green.index(
                          invoke_line) - 800):self.require_green.index(
                              invoke_line) + len(invoke_line)])

    def test_publish_consumes_same_tooling_sha(self):
        publish = self.text[self.text.index("\n  publish:"):]
        self.assertIn("needs.require-green.outputs.tooling_sha", publish)
        self.assertIn("tooling_sha", self.require_green)

    def test_tooling_resolution_accepts_qualified_refs(self):
        """P2: an already-qualified tools_ref (refs/heads/..., refs/tags/...)
        must resolve via unprefixed passthrough, not double-prefix and abort.
        The unqualified bootstrap scope (short tag/branch names) is preserved."""
        self.assertIn("refs/tags/$TOOLS_REF", self.require_green)
        self.assertIn("refs/heads/$TOOLS_REF", self.require_green)
        self.assertRegex(self.require_green, r"\^refs/")
        ls_remotes = [line for line in self.require_green.splitlines()
                      if "git ls-remote" in line]
        self.assertTrue(ls_remotes, "no ls-remote in require-green")
        self.assertTrue(
            any('"$TOOLS_REF"' in line for line in ls_remotes),
            "no ls-remote passes the qualified ref through unprefixed")


class VersionScopeTest(unittest.TestCase):
    """Explicit v0.1.0-only early refusal (QUAL-05)."""

    ASSEMBLE = ROOT / "packaging" / "release" / "assemble.py"

    def run_assemble(self, tag):
        return subprocess.run(
            [sys.executable, str(self.ASSEMBLE), "--tag", tag,
             "--src", "/nonexistent-src", "--pins", "/nonexistent-pins",
             "--staging", "/nonexistent-staging", "--work", "/nonexistent-work",
             "--out", "/nonexistent-out"],
            capture_output=True, text=True, timeout=60)

    def test_v020_refused_early(self):
        proc = self.run_assemble("v0.2.0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("only v0.1.0 is supported", proc.stderr)

    def test_refusal_never_echoes_input(self):
        proc = self.run_assemble("v0.2.0")
        self.assertNotIn("v0.2.0", proc.stderr)
        self.assertNotIn("v0.2.0", proc.stdout)

    def test_v010_passes_version_gate(self):
        proc = self.run_assemble("v0.1.0")
        self.assertNotIn("only v0.1.0 is supported",
                         proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
