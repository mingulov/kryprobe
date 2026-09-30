#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble the unified demo-guest initramfs (attempt 4).

Inputs (all explicit paths, nothing from ambient caches):
  guest init + run-cells.sh + observer-handoff.service (worktree),
  static guest tools (algd/dmap/iochk), busybox, decompressed .ko
  modules, kryprobe CLI + BPF objects + runtime libs.

Output: one deterministic cpio.gz (see ``cpio.py``) plus the
in-image manifest ``/etc/demo/SHA256SUMS`` that the guest init
verifies before any workload. The builder packs twice and refuses
on any byte difference (reproducibility self-check).

Recorded stdout: ``sha256 <digest> bytes <n>`` for the freeze step.
"""

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from kcrypto_qemu_demo import cpio  # noqa: E402

APPLETS = [
    "awk", "basename", "blockdev", "cat", "chmod", "cp", "cut", "date",
    "dd", "dirname", "dmesg", "echo", "env", "find", "free", "grep",
    "head", "hexdump", "insmod", "kill", "ln", "ls", "lsmod", "mkdir",
    "mktemp", "modprobe", "mount", "mv", "od", "poweroff", "ps",
    "readlink", "realpath", "rm", "rmmod", "sed", "seq", "setsid",
    "sh", "sha256sum", "sleep", "sort", "stat", "sync", "sysctl",
    "tail", "tee", "test", "time", "timeout", "touch", "tr", "uname",
    "uniq", "uptime", "wc", "xargs", "xxd",
]

MODULES = [
    "af_alg.ko",
    "algif_hash.ko",
    "algif_skcipher.ko",
    "dm-crypt.ko",
    "aesni-intel.ko",
    "crypto_engine.ko",
    "virtio_crypto.ko",
]

KREL = "7.0.14-070014-generic"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(args) -> tuple[bytes, dict[str, str]]:
    guest_dir = Path(args.guest_dir)
    tools_dir = Path(args.tools_dir)
    modules_dir = Path(args.modules_dir)
    kryprobe_dir = Path(args.kryprobe_dir)
    libs_dir = Path(args.libs_dir)
    staged: dict[str, Path] = {}
    staged["init"] = guest_dir / "init"
    staged["sbin/run-cells.sh"] = guest_dir / "run-cells.sh"
    staged["etc/demo/observer-handoff.service"] = (
        guest_dir / "observer-handoff.service"
    )
    staged["bin/busybox"] = Path(args.busybox)
    for tool in ("algd", "dmap", "iochk"):
        staged[f"opt/demo/bin/{tool}"] = tools_dir / tool
    for module in MODULES:
        staged[f"lib/modules/{KREL}/{module}"] = modules_dir / module
    staged["opt/kryprobe/bin/kryprobe"] = kryprobe_dir / "kryprobe"
    for obj in ("kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o"):
        staged[f"opt/kryprobe/bin/kryprobe-bpf/{obj}"] = (
            kryprobe_dir / "kryprobe-bpf" / obj
        )
    for lib in ("ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"):
        staged[f"lib/demo/{lib}"] = libs_dir / lib
    for name, src in sorted(staged.items()):
        if not src.is_file():
            raise SystemExit(f"build_initramfs: missing input {name} <- {src}")
    manifest_lines = "".join(
        f"{sha256_file(src)}  /{name}\n" for name, src in sorted(staged.items())
    )
    entries: list[cpio.Entry] = []
    for directory in ("bin", "sbin", "etc", "etc/demo", "dev", "proc",
                      "sys", "run", "run/demo", "tmp", "opt", "opt/demo",
                      "opt/demo/bin", "opt/kryprobe", "opt/kryprobe/bin",
                      "opt/kryprobe/bin/kryprobe-bpf", "lib",
                      "lib/modules", f"lib/modules/{KREL}", "lib/demo",
                      "lib64", "lib/x86_64-linux-gnu", "sysroot"):
        entries.append(cpio.dir_entry(directory))
    for applet in APPLETS:
        entries.append(cpio.symlink_entry(f"bin/{applet}", "busybox"))
    # Dynamic loader + libc in their canonical guest paths (copies).
    entries.append(cpio.symlink_entry("lib64/ld-linux-x86-64.so.2",
                                      "../lib/demo/ld-linux-x86-64.so.2"))
    entries.append(cpio.symlink_entry("lib/x86_64-linux-gnu/libc.so.6",
                                      "../../lib/demo/libc.so.6"))
    entries.append(cpio.symlink_entry("lib/x86_64-linux-gnu/libgcc_s.so.1",
                                      "../../lib/demo/libgcc_s.so.1"))
    for name, src in staged.items():
        is_exec = (name == "init" or "/bin/" in name
                   or name.endswith(".sh") or name == "bin/busybox"
                   or name.endswith("ld-linux-x86-64.so.2"))
        mode = 0o755 if is_exec else 0o644
        entries.append(cpio.file_entry(name, src.read_bytes(), mode=mode))
    entries.append(
        cpio.file_entry("etc/demo/SHA256SUMS",
                        manifest_lines.encode(), mode=0o644)
    )
    blob = cpio.build_cpio_gz(entries)
    again = cpio.build_cpio_gz(entries)
    if blob != again:
        raise SystemExit("build_initramfs: nondeterministic pack (refusing)")
    return blob, {name: sha256_file(src) for name, src in staged.items()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="build unified demo initramfs")
    parser.add_argument("--guest-dir", required=True)
    parser.add_argument("--tools-dir", required=True)
    parser.add_argument("--busybox", required=True)
    parser.add_argument("--modules-dir", required=True)
    parser.add_argument("--kryprobe-dir", required=True)
    parser.add_argument("--libs-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    blob, _ = build(args)
    Path(args.out).write_bytes(blob)
    print(f"sha256 {hashlib.sha256(blob).hexdigest()} bytes {len(blob)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
