#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Thin CLI for the kcrypto QEMU demo campaign (P10).

- ``plan --manifest INPUTS.json``: read-only validation of the frozen
  run manifest (never boots, never writes beside the manifest).
- ``run --manifest INPUTS.json --cell D01 --run-dir RUN``: requires a
  fresh owned directory and the exclusive lane; boots one owned
  guest, runs the cell within its frozen budget, stops + reaps the
  guest, seals the receipts, and judges the cell offline.
- ``verify --run-dir RUN``: offline reconciliation of sealed receipts
  (never boots, never repairs a run).

Exit status: 0 PASS, 1 FAIL/error, 2 usage, 3 NOT_RUN/UNSUPPORTED.
Attempt 4 implements every workload kind except ``nested-fallback``
(D06), whose X01 prerequisite is proven absent and seals
UNSUPPORTED without booting. Unknown kinds seal NOT_RUN without
booting — never a PASS.
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from kcrypto_qemu_demo import cells, receipts, reconcile, runner  # noqa: E402

IMPLEMENTED_WORKLOADS = frozenset({
    "cold-boot-no-observer",
    "provider-selection",
    "cpu-variant",
    "dmcrypt-io",
    "virtio-device",
    "device-removal",
    "early-boot",
    "stop-soak",
})

# Workload kinds with no live implementation whose prerequisite is
# proven absent (sealed UNSUPPORTED without booting, never a PASS).
UNSUPPORTED_WORKLOADS = {
    "nested-fallback": (
        "X01 threshold provider absent from the tree and no kernel"
        " source to port it; no real-driver fallback trigger"
        " qualified with exact source + live evidence"
    ),
}

PRODUCT_PIN_NAMES = ["kryprobe", "kcrypto.bpf.o", "kcrypto-lifecycle.bpf.o"]

EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_NOT_RUN = 0, 1, 2, 3


def cmd_plan(args) -> int:
    try:
        manifest = receipts.load_manifest(Path(args.manifest))
    except (receipts.InputError, OSError) as err:
        print(f"plan: refused: {err}", file=sys.stderr)
        return EXIT_FAIL
    print(f"manifest: {args.manifest}")
    print(f"sha256: {manifest['_manifest_sha256']}")
    print(f"cells: {' '.join(cell['id'] for cell in manifest['cells'])}")
    for cell in manifest["cells"]:
        print(
            f"  {cell['id']}: image={cell['image']} "
            f"timeout={cell['limits']['timeout_s']}s "
            f"workload={cell['workload'].get('kind')}"
        )
    return EXIT_PASS


def _not_run_receipt(run_dir: Path, run_id: str, cell_id: str, reason: str) -> Path:
    receipt = {
        "$schema": receipts.SCHEMA_CELL,
        "run_id": run_id,
        "cell_id": cell_id,
        "verdict": "NOT_RUN",
        "reason": reason,
        "positive_control": "T01-harness cold boot",
    }
    path = run_dir / f"cell-{cell_id}.json"
    receipts.atomic_write_json(path, receipt)
    return path


def cmd_run(args) -> int:
    manifest_path = Path(args.manifest)
    run_dir = Path(args.run_dir)
    try:
        manifest = receipts.load_manifest(manifest_path)
    except (receipts.InputError, OSError) as err:
        print(f"run: refused: {err}", file=sys.stderr)
        return EXIT_FAIL
    by_id = {cell["id"]: cell for cell in manifest["cells"]}
    if args.cell not in by_id:
        print(f"run: unknown cell {args.cell!r}", file=sys.stderr)
        return EXIT_USAGE
    cell = by_id[args.cell]
    if run_dir.exists():
        print(f"run: refusing to reuse existing {run_dir}", file=sys.stderr)
        return EXIT_FAIL
    run_dir.mkdir(mode=0o700, parents=True)
    # Campaign run ID: the parent campaign dir when this cell runs
    # inside one (parent holds INPUTS.json), else the dir itself.
    campaign_parent = run_dir.resolve().parent
    if (campaign_parent / "INPUTS.json").is_file():
        run_id = campaign_parent.name
    else:
        run_id = run_dir.name
    receipts.atomic_write_json(
        run_dir / "run.json",
        {
            "run_id": run_id,
            "cell_id": cell["id"],
            "manifest_sha256": manifest["_manifest_sha256"],
            "timeout_s": cell["limits"]["timeout_s"],
            "workload": cell["workload"],
        },
    )
    kind = cell["workload"].get("kind")
    if kind in UNSUPPORTED_WORKLOADS:
        receipt = cells.unsupported_receipt(
            cell, run_id, UNSUPPORTED_WORKLOADS[kind],
            manifest["_manifest_sha256"])
        receipt["harness_commit"] = receipts.harness_commit(HERE.parent)
        path = run_dir / f"cell-{cell['id']}.json"
        receipts.atomic_write_json(path, receipt)
        receipts.seal_artifacts(run_dir, ["run.json", path.name],
                                writers_done=True)
        print(json.dumps({"cell": cell["id"], "verdict": "UNSUPPORTED",
                          "reason": receipt["reason"]}))
        return EXIT_NOT_RUN
    if kind not in IMPLEMENTED_WORKLOADS:
        path = _not_run_receipt(
            run_dir, run_id, cell["id"],
            f"workload kind {kind!r} is not implemented",
        )
        receipts.seal_artifacts(run_dir, ["run.json", path.name], writers_done=True)
        print(json.dumps({"cell": cell["id"], "verdict": "NOT_RUN", "reason": path.name}))
        return EXIT_NOT_RUN
    if kind == "cold-boot-no-observer":
        seal_ledgers = [f"cell-{cell['id']}.json"]
    else:
        try:
            seal_ledgers = cells.check_evidence_cover(cell)
        except cells.CellError as err:
            print(f"run: evidence skew refused: {err}", file=sys.stderr)
            return EXIT_FAIL
    images = {image["id"]: image for image in manifest["images"]}
    image = images[cell["image"]]
    qmp_device = None
    if kind == "device-removal":
        if len(image["devices"]) != 1:
            print("run: device-removal needs an image with exactly one"
                  f" device, {cell['image']!r} has"
                  f" {len(image['devices'])}", file=sys.stderr)
            return EXIT_FAIL
        qmp_device = image["devices"][0]
    lock_paths = [Path(p) for p in args.lock]
    try:
        guest = runner.launch_guest(
            manifest=manifest,
            image_id=cell["image"],
            run_dir=run_dir,
            name=f"kcrypto-demo-{cell['id']}",
            lock_paths=lock_paths,
            needs_data_disk=bool(cell["workload"].get("needs_data_disk")),
            cell_id=cell["id"],
            refuse_foreign=args.refuse_foreign,
        )
    except (runner.GuestError, OSError) as err:
        print(f"run: launch refused: {err}", file=sys.stderr)
        return EXIT_FAIL
    try:
        receipt_path = runner.run_cell(
            guest=guest,
            cell=cell,
            run_dir=run_dir,
            run_id=run_id,
            manifest_sha256=manifest["_manifest_sha256"],
            qmp_device=qmp_device,
        )
    finally:
        stop = runner.stop_guest(guest)
    finalized = receipts.finalize_cell_receipt(receipt_path, stop)
    finalized["custody"]["hashes_unchanged"] = True
    finalized["harness_commit"] = receipts.harness_commit(HERE.parent)
    finalized["pins"] = {
        "kryprobe": manifest["product"]["cli_sha"],
        "kcrypto.bpf.o": manifest["product"]["bpf_agg_sha"],
        "kcrypto-lifecycle.bpf.o": manifest["product"]["bpf_lc_sha"],
    }
    finalized["executed"] = dict(finalized["pins"])
    receipts.atomic_write_json(receipt_path, finalized)
    names = ["run.json", "spawn.json", "stop.json", "console.log",
             *seal_ledgers]
    try:
        sums = receipts.seal_artifacts(run_dir, names, writers_done=True)
    except (FileNotFoundError, ValueError) as err:
        print(f"run: seal refused: {err}", file=sys.stderr)
        return EXIT_FAIL
    judged = reconcile.reconcile_cell(finalized)
    print(json.dumps({
        "cell": cell["id"],
        "verdict": judged["verdict"],
        "reasons": judged["reasons"],
        "sha256sums": sums,
    }))
    if judged["verdict"] == "PASS":
        return EXIT_PASS
    if judged["verdict"] in ("NOT_RUN", "UNSUPPORTED"):
        return EXIT_NOT_RUN
    return EXIT_FAIL


def cmd_verify(args) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"verify: no such run dir {run_dir}", file=sys.stderr)
        return EXIT_USAGE
    sealed = (run_dir / "SHA256SUMS").is_file()
    found = sorted(run_dir.glob("cell-*.json"))
    if not found:
        print("verify: no cell receipts", file=sys.stderr)
        return EXIT_FAIL
    receipts_list = [json.loads(path.read_text()) for path in found]
    required = [item.get("cell_id", "?") for item in receipts_list]
    judged = reconcile.reconcile_campaign(
        required, receipts_list, uniform_pins=PRODUCT_PIN_NAMES
    )
    if not sealed:
        judged["reasons"].append("run dir is unsealed (SHA256SUMS missing)")
        judged["verdict"] = "FAIL"
    else:
        for problem in receipts.check_seal_contents(run_dir):
            judged["reasons"].append(problem)
            judged["verdict"] = "FAIL"
        covered = receipts.sealed_names(run_dir)
        required = {"run.json"}
        for path in sorted(run_dir.iterdir()):
            if path.is_file() and path.name != "SHA256SUMS":
                required.add(path.name)
        for name in sorted(required - covered):
            if name.startswith("cell-") and name.endswith(".json"):
                judged["reasons"].append(
                    f"adjudicated receipt {name!r} is not sealed")
            else:
                judged["reasons"].append(f"run artifact {name!r} is not sealed")
            judged["verdict"] = "FAIL"
    for cell_id in sorted(judged["per_cell"]):
        print(f"{cell_id}: {judged['per_cell'][cell_id]}")
    for reason in judged["reasons"]:
        print(f"reason: {reason}")
    print(f"campaign: {judged['verdict']}")
    return EXIT_PASS if judged["verdict"] == "PASS" else EXIT_FAIL


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="kcrypto QEMU demo campaign CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="validate the frozen run manifest (read-only)")
    plan.add_argument("--manifest", required=True)
    plan.set_defaults(func=cmd_plan)
    run = sub.add_parser("run", help="boot one owned guest and run one cell")
    run.add_argument("--manifest", required=True)
    run.add_argument("--cell", required=True)
    run.add_argument("--run-dir", required=True)
    run.add_argument("--lock", action="append", default=[],
                     help="exclusive lane lock (repeatable, at least one)")
    run.add_argument("--refuse-foreign", action="store_true",
                     help="refuse launch when foreign qemu exists"
                     " (otherwise the preexisting set is recorded)")
    run.set_defaults(func=cmd_run)
    verify = sub.add_parser("verify", help="reconcile sealed receipts (offline)")
    verify.add_argument("--run-dir", required=True)
    verify.set_defaults(func=cmd_verify)
    args = parser.parse_args(argv)
    if args.command == "run" and not args.lock:
        print("run: at least one --lock is required", file=sys.stderr)
        return EXIT_USAGE
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
