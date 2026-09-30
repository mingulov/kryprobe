#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify release staging bytes against git-pinned hashes (fail closed).

Every staging input is untrusted until it matches packaging/release-pins.json
exactly. Any mismatch, missing file, count drift, symlink, absolute path or
parent escape aborts with nonzero exit and names the offender.

Usage: verify-inputs.py --pins PINS --staging DIR --out JSON
"""
import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def fail(msg):
    print(f"verify-inputs: REFUSED: {msg}", file=sys.stderr)
    return 1


def verify_evidence(asset, spec, failures):
    """Stream-decode one .tar.zst and check every member against its seal."""
    name = asset.name
    want_archive = spec["archive"]
    actual = digest(asset)
    if actual != want_archive["sha256"] or asset.stat().st_size != want_archive["bytes"]:
        failures.append(f"{name}: archive hash/size mismatch")
        return
    try:
        decoder = subprocess.Popen(["zstd", "-d", "-q", "-c", str(asset)], stdout=subprocess.PIPE)
    except FileNotFoundError:
        failures.append(f"{name}: zstd CLI missing on runner")
        return
    sealed = {}
    seal_rel = f"{spec['root']}/{spec['seal']}"
    members = {}
    try:
        with tarfile.open(fileobj=decoder.stdout, mode="r|") as archive:
            for member in archive:
                p = PurePosixPath(member.name)
                if p.is_absolute() or ".." in p.parts or member.issym() or member.islnk():
                    failures.append(f"{name}: unsafe member {member.name}")
                    return
                if member.isdir():
                    continue
                if not member.isfile() or member.name in members:
                    failures.append(f"{name}: bad/duplicate member {member.name}")
                    return
                with archive.extractfile(member) as stream:
                    members[member.name] = {
                        "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
                        "bytes": member.size,
                    }
    finally:
        rc = decoder.wait()
    if rc != 0:
        failures.append(f"{name}: zstd decode failed rc={rc}")
        return
    if seal_rel not in members:
        failures.append(f"{name}: seal {seal_rel} absent from archive")
        return
    # Re-read the seal content through a second decode to parse entries.
    decoder = subprocess.Popen(["zstd", "-d", "-q", "-c", str(asset)], stdout=subprocess.PIPE)
    seal_text = None
    with tarfile.open(fileobj=decoder.stdout, mode="r|") as archive:
        for member in archive:
            if member.isfile() and member.name == seal_rel:
                with archive.extractfile(member) as stream:
                    seal_text = stream.read().decode()
    decoder.wait()
    if hashlib.sha256(seal_text.encode()).hexdigest() != spec["seal_sha256"]:
        failures.append(f"{name}: seal digest mismatch vs pins")
        return
    for line in seal_text.splitlines():
        want, sep, filename = line.partition("  ")
        if not sep or len(want) != 64:
            failures.append(f"{name}: malformed seal line")
            return
        sealed[f"{spec['root']}/{filename.removeprefix('./')}"] = want
    if len(sealed) != spec["sealed_entries"]:
        failures.append(f"{name}: sealed count {len(sealed)} != {spec['sealed_entries']}")
        return
    if len(members) != spec["archived_files"]:
        failures.append(f"{name}: member count {len(members)} != {spec['archived_files']}")
        return
    for rel, want in sealed.items():
        if rel not in members:
            failures.append(f"{name}: sealed file missing {rel}")
            return
        if members[rel]["sha256"] != want:
            failures.append(f"{name}: sealed bytes differ {rel}")
            return
    print(f"verify-inputs: {name}: {len(members)} members, seal {spec['seal_sha256'][:12]}... OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pins", required=True)
    ap.add_argument("--staging", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    pins = json.loads(Path(args.pins).read_text())
    staging = Path(args.staging)
    failures = []

    expected = {"kryprobe-v0.1.0-linux-x86_64.tar.gz", "kryprobe-v0.1.0-source.tar.gz",
                *pins["staging_archives"]}
    have = {p.name for p in staging.iterdir() if p.is_file()}
    if not expected <= have:
        return fail(f"staging inputs missing={sorted(expected - have)}")
    for extra in sorted(have - expected):
        print(f"verify-inputs: ignoring non-input staging file {extra} (rebuilt, never trusted)")

    key = {"t14": "kryprobe-v0.1.0-evidence-t14.tar.zst",
           "demo-p10a4": "kryprobe-v0.1.0-evidence-demo-p10a4.tar.zst",
           "demo-p10a7": "kryprobe-v0.1.0-evidence-demo-p10a7.tar.zst",
           "floor-correction": "kryprobe-v0.1.0-evidence-floor-correction.tar.zst"}
    for label, spec in pins["evidence_seals"].items():
        spec = dict(spec)
        spec["archive"] = pins["staging_archives"][key[label]]
        verify_evidence(staging / key[label], spec, failures)

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
    except OSError as exc:
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
    if rep.get("kcrypto", {}).get("sha256") != pins["payload"]["bpf_api"]:
        return fail("staged binary self-reported api BPF mismatch")
    if rep.get("kcrypto_lifecycle", {}).get("sha256") != pins["payload"]["bpf_lifecycle"]:
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
        "evidence_archives_verified": sorted(key.values()),
        "payload_verified": want_payload,
        "vendor_tree_sha256": pins["vendor_tree_sha256"],
        "verdict": "INPUTS_VERIFIED",
    }, indent=2) + "\n")
    print("verify-inputs: ALL STAGING INPUTS VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
