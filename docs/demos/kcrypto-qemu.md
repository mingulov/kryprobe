<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto QEMU demo (P10): reproduction + viewer narration

Status (attempt 2, `p10a2-20260930T000653Z`): Task 1 DONE. Host
suite 70/70 GREEN; T01-harness cold boot PASS (sealed); D01–D08
sealed NOT_RUN (workload kinds unimplemented — no boots, no PASS
claimed). Attempt 1 (`p10a1-20260929T233833Z`) authored the same
files but never executed them (FD-exhaustion BLOCKED). See
`.outbox/kcrypto-demo-qemu/HANDOFF-a2.md` (PARTIAL).

## Reproduce (attempt 2+)

Prerequisites: the frozen run manifest. Copy
`tests/kcrypto_qemu_demo/cells.json` (topology) and
`tests/kcrypto_qemu_demo/guest/image-manifest.json` (template),
measure the exact bytes (QEMU executable, vmlinuz, initramfs,
rootfs, CLI, both BPF objects), and write `INPUTS.json`
(schema `kcrypto.qemu-demo.inputs/v1`). Freeze rule: the manifest
sha256 binds the run; any input change invalidates sealed receipts.

```sh
# worktree root, isolated target/tmp, exclusive lane lock held by run
python3 scripts/kcrypto-qemu-demo.py plan --manifest INPUTS.json
python3 scripts/kcrypto-qemu-demo.py run --manifest INPUTS.json \
  --cell T01-harness --run-dir /path/to/fresh/run \
  --lock /path/to/.artifacts/locks/kcrypto-demo-qemu.lock
python3 scripts/kcrypto-qemu-demo.py verify --run-dir /path/to/fresh/run
```

`plan` is read-only. `run` needs a fresh owned directory and the
exclusive lane (one guest at a time; never touch foreign
VMs/overlays). `verify` is offline: it never boots or repairs.

Host gates (no KVM needed):

```sh
python3 -B -m unittest discover -s tests/kcrypto_qemu_demo -v
```

 Budgets: 180 s ordinary cells, 300 s boot cells, 1500 s D08 soak
including cleanup. A timeout, skip, incomplete reference or stale
artifact can never yield PASS.

## Viewer narration (8–12 minute story, when qualified)

1. Available vs selected (D01): the registry lists providers; one
   allocation selects one driver. Registered-but-unused stays
   "available", never "used".
2. Fresh vs held (D02): a new transform selects under the new CPU
   flags; the held handle does not migrate.
3. Real disk (D03): guest-only dm-crypt writes/reads 64 MiB; the
   workload ledger and the product view agree on bytes, counted
   separately from API calls.
4. Virtual device / fallback (D04–D06): only with proved queue and
   binding evidence; otherwise the claim stops at driver selection
   and the device stays "unknown".
5. Early boot (D07): the observer attaches before the controlled
   unlock; everything before attach is UNOBSERVED.
6. Honest unknowns (D08): loss, caps and stops are explicit; the
   timeline labels every arrow observed/reference/inferred/unknown
   with its run ID, and replay is labeled replay.

No firmware-to-userspace completeness claim, no transparent
failover claim, no physical-accelerator claim, no secret material
in any output.
