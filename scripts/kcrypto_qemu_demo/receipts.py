#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned run manifests, cell receipts and artifact sealing (P10).

Task 1 freezes every input before the first guest boot. The frozen
run manifest (schema ``kcrypto.qemu-demo.inputs/v1``) names the
exact product commit, CLI/BPF digests, QEMU executable, guest
images (kernel/rootfs/initramfs/CPU/devices) and the D01-D08 cell
IDs with their bounded budgets. Anything else — unknown schema,
unknown custody-affecting field, unknown cell ID, unbudgeted
timeout, mismatched artifact hash — refuses loudly: no receipt,
no QMP mutation, no PASS.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SCHEMA_INPUT = "kcrypto.qemu-demo.inputs/v1"
SCHEMA_CELL = "kcrypto.qemu-demo.cell/v1"

REQUIRED_TOP_KEYS = frozenset(
    {
        "$schema",
        "campaign",
        "manifest_version",
        "frozen_utc",
        "freeze_rule",
        "product",
        "qemu",
        "images",
        "cells",
    }
)

REQUIRED_PRODUCT_KEYS = frozenset({"repo_sha", "cli_sha", "bpf_agg_sha", "bpf_lc_sha"})

REQUIRED_QEMU_KEYS = frozenset({"path", "version", "sha256"})

REQUIRED_IMAGE_KEYS = frozenset(
    {
        "id",
        "kernel",
        "vmlinuz",
        "vmlinuz_sha256",
        "config_sha256",
        "initramfs",
        "initramfs_sha256",
        "rootfs",
        "rootfs_sha256",
        "rootfs_format",
        "cpu",
        "devices",
    }
)

REQUIRED_CPU_KEYS = frozenset({"model", "flags"})

REQUIRED_CELL_KEYS = frozenset(
    {"id", "title", "image", "workload", "limits", "expected_evidence"}
)

KNOWN_CELLS = frozenset(
    {"T01-harness", "D01", "D02", "D03", "D04", "D05", "D06", "D07",
     "D07-late", "D07-broken", "D08"}
)

# The plan's only bounded budgets: 180 s ordinary, 300 s boot, 1500 s
# 20-minute soak including cleanup. Anything else refuses.
BUDGETS = frozenset({180, 300, 1500})


class InputError(ValueError):
    """Strict loader refusal: not the frozen v1 shape."""


class ArtifactError(ValueError):
    """Staged artifact is missing or not the frozen bytes."""


def sha256_file(path: Path) -> str:
    """sha256 of one artifact file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_json(path: Path, obj: dict) -> None:
    """Write JSON atomically (tmp + fsync + rename)."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def load_manifest(path: Path) -> dict:
    """Load and strictly validate the frozen run manifest.

    Returns the manifest with ``_manifest_sha256`` binding the exact
    input bytes. Raises :class:`InputError` on any deviation — never
    a partial manifest.
    """
    raw = Path(path).read_bytes()
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as err:
        raise InputError(f"manifest is not valid JSON: {err}") from err
    if not isinstance(manifest, dict):
        raise InputError("manifest top level must be an object")
    missing = REQUIRED_TOP_KEYS - manifest.keys()
    if missing:
        raise InputError(f"manifest missing required keys: {sorted(missing)}")
    unknown = set(manifest.keys()) - REQUIRED_TOP_KEYS
    if unknown:
        raise InputError(f"unknown manifest keys: {sorted(unknown)}")
    if manifest["$schema"] != SCHEMA_INPUT:
        raise InputError(
            f"unknown manifest schema {manifest['$schema']!r} (want {SCHEMA_INPUT!r})"
        )
    if type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 1:
        raise InputError(
            f"unknown manifest_version {manifest['manifest_version']!r} (want int 1)"
        )
    product = manifest["product"]
    if not isinstance(product, dict):
        raise InputError("manifest 'product' must be an object")
    unknown_product = set(product.keys()) - REQUIRED_PRODUCT_KEYS
    if unknown_product:
        raise InputError(f"unknown product keys: {sorted(unknown_product)}")
    missing_product = REQUIRED_PRODUCT_KEYS - set(product.keys())
    if missing_product:
        raise InputError(f"manifest 'product' missing keys: {sorted(missing_product)}")
    qemu = manifest["qemu"]
    if not isinstance(qemu, dict):
        raise InputError("manifest 'qemu' must be an object")
    if set(qemu.keys()) != REQUIRED_QEMU_KEYS:
        raise InputError(
            "manifest 'qemu' keys must be exactly "
            f"{sorted(REQUIRED_QEMU_KEYS)}, got {sorted(qemu.keys())}"
        )
    images = manifest["images"]
    if not isinstance(images, list) or not images:
        raise InputError("manifest 'images' must be a non-empty list")
    image_ids: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            raise InputError("every image must be an object")
        if set(image.keys()) != REQUIRED_IMAGE_KEYS:
            raise InputError(
                f"image {image.get('id', '?')!r} keys must be exactly "
                f"{sorted(REQUIRED_IMAGE_KEYS)}, got {sorted(image.keys())}"
            )
        if image["id"] in image_ids:
            raise InputError(f"duplicate image id {image['id']!r}")
        image_ids.add(image["id"])
        cpu = image["cpu"]
        if not isinstance(cpu, dict) or set(cpu.keys()) != REQUIRED_CPU_KEYS:
            raise InputError(
                f"image {image['id']!r} 'cpu' must be exactly "
                f"{sorted(REQUIRED_CPU_KEYS)}"
            )
        if not isinstance(image["devices"], list):
            raise InputError(f"image {image['id']!r} 'devices' must be a list")
        if image["rootfs_format"] not in ("raw", "qcow2"):
            raise InputError(
                f"image {image['id']!r} has unknown rootfs_format "
                f"{image['rootfs_format']!r}"
            )
    cells = manifest["cells"]
    if not isinstance(cells, list) or not cells:
        raise InputError("manifest 'cells' must be a non-empty list")
    cell_ids: set[str] = set()
    for cell in cells:
        if not isinstance(cell, dict):
            raise InputError("every cell must be an object")
        if set(cell.keys()) != REQUIRED_CELL_KEYS:
            raise InputError(
                f"cell {cell.get('id', '?')!r} keys must be exactly "
                f"{sorted(REQUIRED_CELL_KEYS)}, got {sorted(cell.keys())}"
            )
        if cell["id"] not in KNOWN_CELLS:
            raise InputError(f"unknown cell id {cell['id']!r}")
        if cell["id"] in cell_ids:
            raise InputError(f"duplicate cell id {cell['id']!r}")
        cell_ids.add(cell["id"])
        if cell["image"] not in image_ids:
            raise InputError(
                f"cell {cell['id']!r} references unknown image {cell['image']!r}"
            )
        if not isinstance(cell["workload"], dict) or not cell["workload"]:
            raise InputError(f"cell {cell['id']!r} 'workload' must be nonempty")
        limits = cell["limits"]
        if not isinstance(limits, dict) or set(limits.keys()) != {"timeout_s"}:
            raise InputError(f"cell {cell['id']!r} 'limits' must be exactly timeout_s")
        if type(limits["timeout_s"]) is not int or limits["timeout_s"] not in BUDGETS:
            raise InputError(
                f"cell {cell['id']!r} has unbudgeted timeout_s "
                f"{limits['timeout_s']!r} (want one of {sorted(BUDGETS)})"
            )
        evidence = cell["expected_evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise InputError(
                f"cell {cell['id']!r} 'expected_evidence' must be a non-empty list"
            )
    manifest["_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return manifest


def verify_artifact(path: Path, expected_sha256: str) -> str:
    """Require staged bytes to equal the frozen pin.

    Returns the actual digest. Raises :class:`ArtifactError` when the
    file is missing or the hash differs — and writes nothing.
    """
    path = Path(path)
    if not path.is_file():
        raise ArtifactError(f"missing artifact: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ArtifactError(
            f"artifact hash mismatch: {path} staged {actual} != frozen {expected_sha256}"
        )
    return actual


def seal_artifacts(run_dir: Path, names: list[str], *, writers_done: bool) -> dict[str, str]:
    """Hash the named run-dir artifacts AFTER writers stop + children reaped.

    Writes ``SHA256SUMS`` into the run dir. Returns name -> sha256.
    """
    if not writers_done:
        raise ValueError(
            "seal_artifacts requires writers_done=True "
            "(finalize writers + reap children first)"
        )
    run_dir = Path(run_dir)
    sums: dict[str, str] = {}
    for name in names:
        target = run_dir / name
        if not target.is_file():
            raise FileNotFoundError(f"seal artifact missing: {target}")
        sums[name] = sha256_file(target)
    lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items()))
    (run_dir / "SHA256SUMS").write_text(lines)
    return sums


def finalize_cell_receipt(receipt_path: Path, stop_fragment: dict) -> dict:
    """Merge the owned stop/cleanup fragment into a cell receipt.

    The receipt is written by ``run_cell`` (process + observation);
    the stop fragment arrives after the guest is reaped. Returns the
    finalized receipt dict.
    """
    receipt_path = Path(receipt_path)
    receipt = json.loads(receipt_path.read_text())
    receipt["process"]["reaped"] = bool(stop_fragment.get("reaped"))
    receipt["cleanup"] = {
        "remaining_owned": stop_fragment.get("remaining_owned_qemu", {}),
        "preexisting_unchanged": stop_fragment.get("preexisting_qemu_unchanged"),
        "preexisting_pid_reused": stop_fragment.get("preexisting_pid_reused", []),
        "vng_exit": stop_fragment.get("vng_exit"),
        "stopped_by_helper": stop_fragment.get("stopped_by_helper"),
    }
    atomic_write_json(receipt_path, receipt)
    return receipt
