#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Freeze a run manifest (inputs/v1) from measured bytes (attempt 4).

Every hash is measured from the exact staged file at freeze time;
nothing is copied from an older manifest. The topology (cells)
comes from ``cells.json``; the three guest images share the
pinned kernel/rootfs/initramfs and differ only in CPU model and
QMP/PCI device topology. The product pins name the P9-accepted RC
bytes (re-measured on the read-only stage copy). Prints the
manifest sha256 for the evidence record.
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from kcrypto_qemu_demo import receipts  # noqa: E402


def build_manifest(args) -> dict:
    topo = json.loads(Path(args.cells).read_bytes())
    sha = receipts.sha256_file
    qemu_path = Path(args.qemu_path)
    vmlinuz = Path(args.vmlinuz)
    config = Path(args.config)
    initramfs = Path(args.initramfs)
    rootfs = Path(args.rootfs)
    cli = Path(args.cli)
    bpf_agg = Path(args.bpf_agg)
    bpf_lc = Path(args.bpf_lc)
    cpu_flags = [flag for flag in args.cpu_flag]
    manifest = {
        "$schema": receipts.SCHEMA_INPUT,
        "campaign": "kcrypto-demo-qemu",
        "manifest_version": 1,
        "frozen_utc": args.frozen_utc,
        "freeze_rule": (
            "all hashes measured from staged bytes at freeze time;"
            " any input change invalidates sealed receipts"
        ),
        "product": {
            "repo_sha": args.repo_sha,
            "cli_sha": sha(cli),
            "bpf_agg_sha": sha(bpf_agg),
            "bpf_lc_sha": sha(bpf_lc),
        },
        "qemu": {
            "path": str(qemu_path),
            "version": args.qemu_version,
            "sha256": sha(qemu_path),
        },
        "images": [
            {
                "id": "img-7014-base",
                "kernel": "7.0.14",
                "vmlinuz": str(vmlinuz),
                "vmlinuz_sha256": sha(vmlinuz),
                "config_sha256": sha(config),
                "initramfs": str(initramfs),
                "initramfs_sha256": sha(initramfs),
                "rootfs": str(rootfs),
                "rootfs_sha256": sha(rootfs),
                "rootfs_format": args.rootfs_format,
                "cpu": {"model": "host", "flags": cpu_flags},
                "devices": [],
            },
            {
                "id": "img-7014-nocrypto",
                "kernel": "7.0.14",
                "vmlinuz": str(vmlinuz),
                "vmlinuz_sha256": sha(vmlinuz),
                "config_sha256": sha(config),
                "initramfs": str(initramfs),
                "initramfs_sha256": sha(initramfs),
                "rootfs": str(rootfs),
                "rootfs_sha256": sha(rootfs),
                "rootfs_format": args.rootfs_format,
                "cpu": {"model": "host,-aes,-vaes",
                        "flags": ["no-aes", "no-vaes"]},
                "devices": [],
            },
            {
                "id": "img-7014-1crypt",
                "kernel": "7.0.14",
                "vmlinuz": str(vmlinuz),
                "vmlinuz_sha256": sha(vmlinuz),
                "config_sha256": sha(config),
                "initramfs": str(initramfs),
                "initramfs_sha256": sha(initramfs),
                "rootfs": str(rootfs),
                "rootfs_sha256": sha(rootfs),
                "rootfs_format": args.rootfs_format,
                "cpu": {"model": "host", "flags": cpu_flags},
                "devices": ["crypto0"],
            },
        ],
        "cells": topo["cells"],
    }
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="freeze run manifest")
    parser.add_argument("--cells", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--frozen-utc", required=True)
    parser.add_argument("--repo-sha", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--bpf-agg", required=True)
    parser.add_argument("--bpf-lc", required=True)
    parser.add_argument("--qemu-path", required=True)
    parser.add_argument("--qemu-version", required=True)
    parser.add_argument("--vmlinuz", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--initramfs", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--rootfs-format", default="qcow2")
    parser.add_argument("--cpu-flag", action="append", default=[])
    args = parser.parse_args(argv)
    manifest = build_manifest(args)
    out = Path(args.out)
    receipts.atomic_write_json(out, manifest)
    loaded = receipts.load_manifest(out)
    print(f"manifest_sha256 {loaded['_manifest_sha256']}")
    print(f"cells {' '.join(c['id'] for c in loaded['cells'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
