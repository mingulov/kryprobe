#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify release staging bytes against git-pinned hashes (fail closed).

Every staging input is untrusted until it matches packaging/release-pins.json
exactly. Any mismatch, missing file, count drift, symlink, absolute path or
parent escape aborts with nonzero exit and names the offender.

Staging holds exactly the payload and vendor input archives. Raw measurement
evidence is never a release input (ADR-0012): any evidence-shaped or otherwise
unexpected staging file is refused. Only the three rebuilt outputs
(RELEASE-MANIFEST.json, RELEASE-NOTES.md, SHA256SUMS) are ignored, never trusted.

Usage: verify-inputs.py --pins PINS --staging DIR --out JSON
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def fail(msg):
    print(f"verify-inputs: REFUSED: {msg}", file=sys.stderr)
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pins", required=True)
    ap.add_argument("--staging", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    pins = json.loads(Path(args.pins).read_text())
    staging = Path(args.staging)
    failures = []

    expected = {"kryprobe-v0.1.0-linux-x86_64.tar.gz", "kryprobe-v0.1.0-source.tar.gz"}
    rebuilt = {"RELEASE-MANIFEST.json", "RELEASE-NOTES.md", "SHA256SUMS"}
    have = {p.name for p in staging.iterdir() if p.is_file()}
    if not expected <= have:
        return fail(f"staging inputs missing={sorted(expected - have)}")
    refused = []
    for extra in sorted(have - expected):
        if extra in rebuilt:
            print(f"verify-inputs: ignoring non-input staging file {extra} (rebuilt, never trusted)")
        else:
            refused.append(extra)
    if refused:
        return fail(f"refusing unexpected staging files (evidence is never a release input): {refused}")

    # Staging binary archive: payload members must equal pins, and the
    # staged binary must self-report the same identities with pins enforced.
    with tarfile.open(staging / "kryprobe-v0.1.0-linux-x86_64.tar.gz", "r:gz") as tar:
        blobs = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
    roots = {n.split("/")[0] for n in blobs}
    if len(roots) != 1:
        failures.append("binary archive: expected single top dir")
        return fail("; ".join(failures))
    top = roots.pop()
    want_payload = {"bin/kryprobe": pins["payload"]["cli"],
                    "bin/kryprobe-bpf/kcrypto.bpf.o": pins["payload"]["bpf_api"],
                    "bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o": pins["payload"]["bpf_lifecycle"]}
    for rel, want in want_payload.items():
        data = blobs.get(f"{top}/{rel}")
        if data is None or hashlib.sha256(data).hexdigest() != want:
            failures.append(f"binary archive: payload mismatch {rel}")
    try:
        manifest = json.loads(blobs.get(f"{top}/manifest.json", b""))
    except (json.JSONDecodeError, UnicodeDecodeError):
        manifest = None
    if not manifest or manifest.get("binary", {}).get("sha256") != pins["payload"]["cli"] or \
            sorted(o.get("sha256") for o in manifest.get("objects", [])) != \
            sorted([pins["payload"]["bpf_api"], pins["payload"]["bpf_lifecycle"]]) or \
            sorted(manifest.get("pin_digests", [])) != \
            sorted([pins["payload"]["bpf_api"], pins["payload"]["bpf_lifecycle"]]):
        failures.append("binary archive: manifest.json identities differ from pins")
    if failures:
        return fail("; ".join(failures))
    # The doctor resolves BPF identities from its stage layout, so run it
    # from a full extraction (removed afterwards), not a lone binary.
    import shutil
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="verify-bin-"))
    try:
        with tarfile.open(staging / "kryprobe-v0.1.0-linux-x86_64.tar.gz", "r:gz") as tar:
            tar.extractall(tmp, filter="data")
        cli = tmp / top / "bin" / "kryprobe"
        proc = subprocess.run([str(cli), "doctor", "--versions", "--json"],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return fail(f"staged binary does not execute: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if proc.returncode != 0:
        return fail(f"doctor --versions rc={proc.returncode}: {proc.stderr[-500:]}")
    try:
        rep = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return fail("doctor --versions is not JSON")
    if not (rep.get("pins_enforced") and rep.get("profile_pins_enforced")):
        return fail("staged binary reports pins not enforced")
    if (rep.get("kcrypto") or {}).get("sha256") != pins["payload"]["bpf_api"]:
        return fail("staged binary self-reported api BPF mismatch")
    if (rep.get("kcrypto_lifecycle") or {}).get("sha256") != pins["payload"]["bpf_lifecycle"]:
        return fail("staged binary self-reported lifecycle BPF mismatch")
    print("verify-inputs: staged payload self-report OK")

    # Staging source archive: vendor/ + LICENSES/dependencies/ tree pin.
    with tarfile.open(staging / "kryprobe-v0.1.0-source.tar.gz", "r:gz") as tar:
        src_blobs = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
    src_roots = {n.split("/")[0] for n in src_blobs}
    if len(src_roots) != 1:
        return fail("source archive: expected single top dir")
    src_top = src_roots.pop()
    entries = []
    for name, data in src_blobs.items():
        rel = name[len(src_top) + 1:]
        if rel.startswith("vendor/") or rel.startswith("LICENSES/dependencies/"):
            entries.append(f"{hashlib.sha256(data).hexdigest()}  {rel}\n")
    entries.sort(key=lambda l: l.split("  ")[1])
    if len(entries) != pins["vendor_tree_files"]:
        return fail(f"vendor tree file count {len(entries)} != {pins['vendor_tree_files']}")
    if hashlib.sha256("".join(entries).encode()).hexdigest() != pins["vendor_tree_sha256"]:
        return fail("vendor tree hash mismatch vs pins")
    print(f"verify-inputs: vendor tree {len(entries)} files OK")

    if failures:
        return fail("; ".join(failures))
    Path(args.out).write_text(json.dumps({
        "staging": str(staging),
        "evidence_excluded": True,
        "payload_verified": want_payload,
        "vendor_tree_sha256": pins["vendor_tree_sha256"],
        "verdict": "INPUTS_VERIFIED",
    }, indent=2) + "\n")
    print("verify-inputs: ALL STAGING INPUTS VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
