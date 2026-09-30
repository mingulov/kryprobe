#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministically assemble the v0.1.0 release from a git tag plus verified inputs.

Inputs: --src (checkout of the release tag), --staging (pin-verified draft
assets, see verify-inputs.py), --pins (packaging/release-pins.json).
Output: --out directory with the nine release files, built TWICE and
byte-compared to prove determinism. Any deviation fails closed.

Usage: assemble.py --tag TAG --src DIR --pins FILE --staging DIR --work DIR --out DIR
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

BUILD_INPUTS = ["crates", "xtask", "packaging", "Cargo.toml", "Cargo.lock",
                "rust-toolchain.toml", ".cargo"]
EVIDENCE_FILES = {"t14": "kryprobe-v0.1.0-evidence-t14.tar.zst",
                  "demo-p10a4": "kryprobe-v0.1.0-evidence-demo-p10a4.tar.zst",
                  "demo-p10a7": "kryprobe-v0.1.0-evidence-demo-p10a7.tar.zst",
                  "floor-correction": "kryprobe-v0.1.0-evidence-floor-correction.tar.zst"}


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def fail(msg):
    print(f"assemble: REFUSED: {msg}", file=sys.stderr)
    return 1


def build_once(src, pins, peel, tree, vendor_files, notices_files, payload, stage_extra, work):
    binary = work / "kryprobe-v0.1.0-linux-x86_64"
    (binary / "bin" / "kryprobe-bpf").mkdir(parents=True)
    (binary / "bin" / "kryprobe").write_bytes(payload["bin/kryprobe"])
    (binary / "bin" / "kryprobe-bpf" / "kcrypto.bpf.o").write_bytes(
        payload["bin/kryprobe-bpf/kcrypto.bpf.o"])
    (binary / "bin" / "kryprobe-bpf" / "kcrypto-lifecycle.bpf.o").write_bytes(
        payload["bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o"])
    (binary / "bin" / "kryprobe").chmod(0o755)
    for extra, data in stage_extra.items():
        (binary / extra).write_bytes(data)
    (binary / "packaging").mkdir()
    shutil.copyfile(src / "packaging/install.sh", binary / "packaging/install.sh")
    shutil.copyfile(src / "LICENSE", binary / "LICENSE")
    shutil.copytree(src / "LICENSES", binary / "LICENSES")
    gpl2 = Path("/usr/share/common-licenses/GPL-2")
    if not gpl2.is_file() or digest(gpl2) != pins["gpl2_text_sha256"]:
        raise SystemExit("GPL-2 text missing or not the pinned bytes")
    shutil.copyfile(gpl2, binary / "LICENSES/GPL-2.0-only.txt")
    for rel, data in notices_files.items():
        target = binary / "LICENSES/dependencies" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def portable_link(match):
        target = match.group(1)
        if "://" in target or target.startswith("#"):
            return match.group(0)
        resolved = posixpath.normpath(posixpath.join("docs/releases", target))
        assert not resolved.startswith("../")
        subprocess.run(["git", "cat-file", "-e", peel + ":" + resolved],
                       cwd=src, check=True, capture_output=True)
        return "](https://github.com/mingulov/kryprobe/blob/" + peel + "/" + resolved + ")"
    notes = re.sub(r"\]\(([^)\s]+)\)", portable_link,
                   (src / "docs/releases/v0.1.0.md").read_text())
    assert notes.count("https://github.com/mingulov/kryprobe/blob/" + peel + "/") == 4
    (binary / "RELEASE-NOTES.md").write_text(notes)

    versions = subprocess.check_output([str(binary / "bin/kryprobe"), "doctor",
                                        "--versions", "--json"], text=True)
    v = json.loads(versions)
    assert v["pins_enforced"] and v["profile_pins_enforced"]
    assert v["kcrypto"]["sha256"] == pins["payload"]["bpf_api"]
    assert v["kcrypto_lifecycle"]["sha256"] == pins["payload"]["bpf_lifecycle"]
    abi = subprocess.check_output(["readelf", "--version-info", str(binary / "bin/kryprobe")], text=True)
    dynamic = subprocess.check_output(["readelf", "-d", str(binary / "bin/kryprobe")], text=True)
    required = sorted(set(re.findall(r"GLIBC_[0-9.]+", abi)),
                      key=lambda x: tuple(map(int, x.split("_")[1].split("."))))
    needed = re.findall(r"Shared library: \[(.*?)\]", dynamic)
    provenance = {"product": "KryProbe", "version": "0.1.0",
                  "publication_status": "PIPELINE_ASSEMBLED",
                  "source_commit": peel, "source_tree": tree,
                  "measured_source_checkpoint": pins["measured_checkpoints"]["t14"],
                  "accepted_demo_checkpoint": pins["measured_checkpoints"]["demo"],
                  "runtime_build_inputs_delta_from_t14": [],
                  "payload_source": "measured T14 payload, pin-verified staging bytes",
                  "payload": [
                      {"path": "bin/kryprobe",
                       "sha256": hashlib.sha256(payload["bin/kryprobe"]).hexdigest()},
                      {"name": "kcrypto.bpf.o", "path": "bin/kryprobe-bpf/kcrypto.bpf.o",
                       "sha256": hashlib.sha256(payload["bin/kryprobe-bpf/kcrypto.bpf.o"]).hexdigest()},
                      {"name": "kcrypto-lifecycle.bpf.o",
                       "path": "bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o",
                       "sha256": hashlib.sha256(payload["bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o"]).hexdigest()},
                  ],
                  "manifest_sha256": digest(binary / "manifest.json"),
                  "target": "x86_64-unknown-linux-gnu",
                  "required_glibc_symbols": required, "needed_libraries": needed,
                  "live_evidence": "accepted T14/P10 evidence at its recorded identities; no new privileged run",
                  "source_archive": "kryprobe-v0.1.0-source.tar.gz"}
    (binary / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (binary / "README.txt").write_text(
        "KryProbe v0.1.0 prepared Linux x86-64 bundle\n\nRequires glibc 2.39+, libgcc_s.so.1, and the documented kernel capabilities.\nVerify: sha256sum -c sha256sums.txt\nInstall: sudo sh packaging/install.sh --stage \"$PWD\"\nVerify installation: kryprobe doctor --versions; kryprobe doctor\n\nThe paired kryprobe-v0.1.0-source.tar.gz contains product and dependency\nsources, notices, lockfiles and build instructions. Read RELEASE-NOTES.md\nfor measured limitations; full performance qualification remains incomplete.\n")

    source = work / "kryprobe-v0.1.0-source"
    source.mkdir()
    archive = subprocess.check_output(["git", "archive", "--format=tar", peel], cwd=src)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for m in tar:
            p = PurePosixPath(m.name)
            assert not p.is_absolute() and ".." not in p.parts
        tar.extractall(source, filter="data")
    for rel, data in vendor_files.items():
        target = source / "vendor" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    shutil.copytree(binary / "LICENSES/dependencies", source / "LICENSES/dependencies")
    shutil.copyfile(gpl2, source / "LICENSES/GPL-2.0-only.txt")
    shutil.copyfile(binary / "PROVENANCE.json", source / "RELEASE-PROVENANCE.json")
    (source / "vendor-config.toml").write_text(
        '# Release-bundle dependency sources; append to .cargo/config.toml to build offline.\n[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "vendor"\n')
    (source / "BUILD-RELEASE.txt").write_text(
        "KryProbe v0.1.0 corresponding source\nSource commit: " + peel + "\nSource tree: " + tree + "\n\nAll tracked product files are identical to that commit. Added bundle files\nare vendor/, vendor-config.toml, dependency/GPL-2 notices, this document\nand RELEASE-PROVENANCE.json. No product source was rewritten.\n\nInstall the toolchains/linker pinned in docs/dependencies/pins.md.\nOptional offline dependencies (from this extracted directory):\n  cat vendor-config.toml >> .cargo/config.toml\nBuild with an absent or empty destination whose parent exists:\n  packaging/build-release.sh --dest /owned/empty-stage\nThrough mise where configured:\n  mise exec -- packaging/build-release.sh --dest /owned/empty-stage\n\nRust standard-library sources and the linker are toolchain prerequisites.\nThe binary bundle preserves the previously measured T14 payload; builds\nfrom a different path/environment may differ in bytes. Runtime sources\nand frozen build inputs are unchanged from accepted T14.\n")
    entries = subprocess.check_output(["git", "ls-tree", "-r", "-z", peel], cwd=src).decode().split("\0")
    entries = [e for e in entries if e]
    assert len(entries) == pins["counts"]["tracked_source_files"], len(entries)
    for entry in entries:
        meta, rel = entry.split("\t")
        mode, _typ, _obj = meta.split(" ")
        want = subprocess.check_output(["git", "show", f"{peel}:{rel}"], cwd=src)
        assert (source / rel).read_bytes() == want, rel
        assert ((source / rel).stat().st_mode & 0o111) == (int(mode, 8) & 0o111), rel
    return binary, source


def pack(root, path, asset_name):
    files = {f"{root.name}/{p.relative_to(root)}": {"sha256": digest(p), "bytes": p.stat().st_size}
             for p in sorted(root.rglob("*")) if p.is_file()}

    def normalize(info):
        assert not info.issym() and not info.islnk(), info.name
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        info.pax_headers = {}
        return info

    with path.open("xb") as f, gzip.GzipFile(fileobj=f, mode="wb", filename="", mtime=0,
                                             compresslevel=6) as zipped:
        with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            tar.add(root, arcname=root.name, filter=normalize)
    seen = {}
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            if member.isdir():
                continue
            assert member.isfile() and member.name in files and member.name not in seen
            with tar.extractfile(member) as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            seen[member.name] = {"sha256": actual, "bytes": member.size}
    assert seen == files
    return {"asset": asset_name, "sha256": digest(path), "bytes": path.stat().st_size,
            "files": len(files), "archive_member_comparison": "ALL_IDENTICAL"}


def consumer_checks(binary, work):
    """Rootless install + version/synthetic/replay probes on the bundle."""
    neutral = work / "consumer"
    env = {k: v for k, v in os.environ.items()
           if k not in ["KRYPROBE_BPF_DIR", "KRYPROBE_BPF_OBJ"]}
    subprocess.run(["sha256sum", "-c", "sha256sums.txt"], cwd=binary,
                   env=env, check=True, capture_output=True)
    subprocess.run(["sh", str(binary / "packaging/install.sh"), "--stage", str(binary),
                    "--destdir", str(neutral / "root"), "--prefix", "/usr", "--no-mint"],
                   cwd=neutral.parent, env=env, check=True, capture_output=True)
    installed = neutral / "root/usr/bin/kryprobe"
    rep = json.loads(subprocess.check_output([str(installed), "doctor", "--versions", "--json"],
                                             env=env, text=True))
    assert rep["pins_enforced"] and rep["profile_pins_enforced"]
    subprocess.run([str(installed), "--version"], env=env, check=True, capture_output=True)
    subprocess.run([str(installed), "selftest", "synthetic", "--out",
                    str(neutral / "synthetic.jsonl")], env=env, check=True, capture_output=True)
    subprocess.run([str(installed), "report", str(neutral / "synthetic.jsonl")],
                   env=env, check=True, capture_output=True)
    print("assemble: consumer checks (install/version/synthetic/replay) OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--pins", required=True)
    ap.add_argument("--staging", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    # Resolve everything: consumer checks run children under foreign cwds,
    # so relative CLI paths would resolve against the wrong directory.
    src = Path(args.src).resolve()
    pins = json.loads(Path(args.pins).resolve().read_text())
    staging = Path(args.staging).resolve()
    work = Path(args.work).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    peel = subprocess.check_output(["git", "-C", str(src), "rev-parse", f"{args.tag}^{{}}"],
                                   text=True).strip()
    tree = subprocess.check_output(["git", "-C", str(src), "rev-parse", f"{peel}^{{tree}}"],
                                   text=True).strip()
    head = subprocess.check_output(["git", "-C", str(src), "rev-parse", "HEAD"], text=True).strip()
    if head != peel:
        return fail(f"src checkout HEAD {head} != tag peel {peel}")
    print(f"assemble: tag {args.tag} peels to {peel}, tree {tree}")
    delta = subprocess.check_output(["git", "-C", str(src), "diff", "--name-only",
                                     pins["measured_checkpoints"]["t14"], peel,
                                     "--", *BUILD_INPUTS], text=True)
    if delta.strip():
        return fail(f"runtime build inputs differ from measured T14: {delta}")
    print("assemble: zero build-input delta vs measured T14")

    with tarfile.open(staging / "kryprobe-v0.1.0-linux-x86_64.tar.gz", "r:gz") as tar:
        stage_bin = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
    bin_top = next(iter({n.split('/')[0] for n in stage_bin}))
    payload = {}
    for rel, want in [("bin/kryprobe", pins["payload"]["cli"]),
                      ("bin/kryprobe-bpf/kcrypto.bpf.o", pins["payload"]["bpf_api"]),
                      ("bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o", pins["payload"]["bpf_lifecycle"])]:
        data = stage_bin.get(f"{bin_top}/{rel}")
        if data is None or hashlib.sha256(data).hexdigest() != want:
            return fail(f"staging payload mismatch {rel}")
        payload[rel] = data
    stage_extra = {}
    for extra in ["manifest.json", "sha256sums.txt"]:
        data = stage_bin.get(f"{bin_top}/{extra}")
        if data is None:
            return fail(f"staging binary archive missing {extra}")
        stage_extra[extra] = data
    try:
        stage_manifest = json.loads(stage_extra["manifest.json"])
    except (json.JSONDecodeError, UnicodeDecodeError):
        stage_manifest = None
    if not stage_manifest or \
            stage_manifest.get("binary", {}).get("sha256") != pins["payload"]["cli"] or \
            sorted(o.get("sha256") for o in stage_manifest.get("objects", [])) != \
            sorted([pins["payload"]["bpf_api"], pins["payload"]["bpf_lifecycle"]]) or \
            sorted(stage_manifest.get("pin_digests", [])) != \
            sorted([pins["payload"]["bpf_api"], pins["payload"]["bpf_lifecycle"]]):
        return fail("staging manifest.json identities differ from pins")

    with tarfile.open(staging / "kryprobe-v0.1.0-source.tar.gz", "r:gz") as tar:
        stage_src = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
    src_top = next(iter({n.split('/')[0] for n in stage_src}))
    vendor_files, notices_files, entries = {}, {}, []
    for name, data in stage_src.items():
        rel = name[len(src_top) + 1:]
        if rel.startswith("vendor/"):
            vendor_files[rel[len("vendor/"):]] = data
            entries.append(f"{hashlib.sha256(data).hexdigest()}  {rel}\n")
        elif rel.startswith("LICENSES/dependencies/"):
            notices_files[rel[len("LICENSES/dependencies/"):]] = data
            entries.append(f"{hashlib.sha256(data).hexdigest()}  {rel}\n")
    entries.sort(key=lambda l: l.split("  ")[1])
    if len(entries) != pins["vendor_tree_files"] or \
            hashlib.sha256("".join(entries).encode()).hexdigest() != pins["vendor_tree_sha256"]:
        return fail("staging vendor tree does not match pins")

    first = work / "build-a"
    binary_a, source_a = build_once(src, pins, peel, tree, vendor_files, notices_files,
                                    payload, stage_extra, first)
    consumer_checks(binary_a, first)
    second = work / "build-b"
    binary_b, source_b = build_once(src, pins, peel, tree, vendor_files, notices_files,
                                    payload, stage_extra, second)
    assets = []
    for root_a, root_b, filename, want in [
            (binary_a, binary_b, "kryprobe-v0.1.0-linux-x86_64.tar.gz",
             pins["counts"]["binary_archive_members"]),
            (source_a, source_b, "kryprobe-v0.1.0-source.tar.gz",
             pins["counts"]["source_archive_members"])]:
        pa, pb = work / ("a-" + filename), work / ("b-" + filename)
        aa = pack(root_a, pa, filename)
        ab = pack(root_b, pb, filename)
        assert ab["sha256"]  # packed identically or pack() already failed
        if pa.read_bytes() != pb.read_bytes():
            return fail(f"nondeterministic build: {filename}")
        if aa["files"] != want:
            return fail(f"{filename}: member count {aa['files']} != {want}")
        shutil.move(str(pa), str(out / filename))
        pb.unlink()
        assets.append(aa)
        print(f"assemble: {filename}: {aa['sha256']} deterministic, {aa['files']} members")

    for label, filename in EVIDENCE_FILES.items():
        spec = pins["staging_archives"][filename]
        blob = staging / filename
        if digest(blob) != spec["sha256"] or blob.stat().st_size != spec["bytes"]:
            return fail(f"evidence input drifted: {filename}")
        shutil.copyfile(blob, out / filename)
        seal = pins["evidence_seals"][label]
        assets.append({"asset": filename, "sha256": spec["sha256"], "bytes": spec["bytes"],
                       "archived_files": seal["archived_files"],
                       "original_root": seal["root"], "original_seal": seal["seal"],
                       "original_seal_sha256": seal["seal_sha256"]})

    notes = (first / "kryprobe-v0.1.0-linux-x86_64" / "RELEASE-NOTES.md").read_text()
    (out / "RELEASE-NOTES.md").write_text(notes)
    manifest = {"product": "KryProbe", "version": "0.1.0",
                "prepared_from_commit": peel, "source_tree": tree,
                "assets": assets, "evidence_preserved": True,
                "runtime_source_changes": False,
                "live_qualification": "original accepted evidence at recorded payload hashes; full R1 remains open"}
    (out / "RELEASE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    order = ["RELEASE-MANIFEST.json", "RELEASE-NOTES.md",
             "kryprobe-v0.1.0-evidence-demo-p10a4.tar.zst",
             "kryprobe-v0.1.0-evidence-demo-p10a7.tar.zst",
             "kryprobe-v0.1.0-evidence-floor-correction.tar.zst",
             "kryprobe-v0.1.0-evidence-t14.tar.zst",
             "kryprobe-v0.1.0-linux-x86_64.tar.gz",
             "kryprobe-v0.1.0-source.tar.gz"]
    (out / "SHA256SUMS").write_text("".join(f"{digest(out / n)}  {n}\n" for n in order))
    back = json.loads((out / "RELEASE-MANIFEST.json").read_text())
    for entry in back["assets"]:
        p = out / entry["asset"]
        assert digest(p) == entry["sha256"] and p.stat().st_size == entry["bytes"], entry["asset"]
    print(f"assemble: dist complete: 9 files, outer seal {digest(out / 'SHA256SUMS')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
