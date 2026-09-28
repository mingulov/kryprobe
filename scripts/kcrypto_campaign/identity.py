#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pre-GO / post-stop identity validation for T13 cells.

Each in-guest scenario records ``identity-before.env`` (before GO)
and ``identity-after.env`` (after stop): ``KEY=VALUE`` lines naming
the kernel release, config hash, BTF hash, fixture-module hash,
CLI hash, BPF object hashes and oracle hash. :func:`compare_identities`
requires every required key present, nonempty and UNCHANGED — a
mid-run kernel/module/binary/identity change invalidates the cell
(changed source invalidates prior evidence).
"""

from __future__ import annotations

REQUIRED_KEYS = frozenset(
    {
        "kernel",
        "config_sha",
        "btf_sha",
        "module_sha",
        "cli_sha",
        "bpf_agg_sha",
        "bpf_lc_sha",
        "oracle_sha",
    }
)

OPTIONAL_KEYS = frozenset({"run_suffix", "fixture_suite"})


class IdentityError(ValueError):
    """Identity file refusal: malformed lines or empty values."""


def parse_identity_env(text: str) -> dict:
    """Parse ``KEY=VALUE`` identity lines into a dict.

    Refuses malformed lines, empty keys/values and duplicate keys
    (an identity file is exact, never best-effort).
    """
    identity: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            raise IdentityError(f"malformed identity line {lineno}: {line!r}")
        key = key.strip()
        if key in identity:
            raise IdentityError(f"duplicate identity key {key!r} on line {lineno}")
        if not value.strip():
            raise IdentityError(f"empty value for identity key {key!r} on line {lineno}")
        identity[key] = value.strip()
    return identity


def compare_identities(before: dict, after: dict) -> dict:
    """Compare pre-GO and post-stop identities.

    Returns ``{"stable": bool, "mismatches": [...], "missing":
    [...]}``. Stable requires every required key present in both
    files with identical values. Unknown extra keys are ignored
    (informational only); missing or changed required keys fail.
    """
    missing = sorted((REQUIRED_KEYS - before.keys()) | (REQUIRED_KEYS - after.keys()))
    mismatches = sorted(
        key for key in REQUIRED_KEYS
        if key in before and key in after and before[key] != after[key]
    )
    stable = not missing and not mismatches
    return {"stable": stable, "mismatches": mismatches, "missing": missing}
