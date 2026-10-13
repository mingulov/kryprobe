#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact-SHA required-jobs verifier for the release gate (QUAL-03).

Pure contract: success requires every required lane successful on exactly the
expected commit, with duplicate required names rejected. Jobs outside the
required set are ignored (a completed-success run conclusion already covers
the whole run). All refusal reasons are static strings: raw run/job input is
never echoed.

The required set mirrors the display names (`name:`) emitted by the SUPPORTED
TAG tree .github/workflows/ci.yml (v0.1.0, peel
bd127cf5e90e7863b2b52a6d3d2685d12d4f8113), not the current tree;
tests/release/test_verify_ci.py pins the two together so tag-tree renames
fail loudly instead of silently widening the gate. Any future supported tag
needs its own lane-set decision; never assume the current tree lanes.

Usage: verify-ci.py --expected-sha SHA --run-json FILE
FILE is one JSON object shaped like `gh run view --json
headSha,status,conclusion,jobs`.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# v0.1.0 tag tree ci.yml display names (host gate, unprivileged BPF lane,
# supply chain). Peel bd127cf5e90e7863b2b52a6d3d2685d12d4f8113. The current
# tree carries a 4th privileged sudo lane that no v0.1.0-peel run can contain;
# scoping to the tag lanes is the P1 deadlock fix. Recheck against the
# supported tag tree on any scope decision, never the current tree.
REQUIRED_JOBS = (
    "host gate",
    "BPF lane (unprivileged)",
    "supply chain",
)

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def validate_required_jobs(expected_sha: str, run: dict, jobs: list) -> list:
    """Return static refusal reasons; [] means the gate accepts."""
    reasons = []
    if not isinstance(run, dict) or run.get("headSha") != expected_sha:
        reasons.append("run head SHA is not the expected commit")
    if (not isinstance(run, dict) or run.get("status") != "completed"
            or run.get("conclusion") != "success"):
        reasons.append("run is not a completed success")
    if not isinstance(jobs, list):
        reasons.append("job list is not a list")
        return reasons
    seen = {}
    for job in jobs:
        if not isinstance(job, dict):
            reasons.append("a job record is not an object")
            continue
        name = job.get("name")
        if name not in REQUIRED_JOBS:
            continue  # unrelated extra: accepted, never trusted
        if name in seen:
            reasons.append(f"duplicate required job: {name}")
        else:
            seen[name] = job.get("conclusion")
    for name in REQUIRED_JOBS:
        if name not in seen:
            reasons.append(f"missing required job: {name}")
        elif seen[name] != "success":
            reasons.append(f"required job did not succeed: {name}")
    return reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--run-json", required=True)
    args = ap.parse_args()
    if not _SHA40.match(args.expected_sha):
        print("verify-ci: REFUSED: expected SHA is not a full commit SHA",
              file=sys.stderr)
        return 1
    try:
        doc = json.loads(Path(args.run_json).read_text())
    except (OSError, ValueError):
        print("verify-ci: REFUSED: run JSON is unreadable", file=sys.stderr)
        return 1
    if not isinstance(doc, dict):
        print("verify-ci: REFUSED: run JSON is not an object", file=sys.stderr)
        return 1
    reasons = validate_required_jobs(
        args.expected_sha, doc, doc.get("jobs"))
    if reasons:
        print(f"verify-ci: REFUSED: {'; '.join(reasons)}", file=sys.stderr)
        return 1
    print(f"verify-ci: ACCEPT: {len(REQUIRED_JOBS)}/{len(REQUIRED_JOBS)} "
          f"required jobs green on the expected commit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
