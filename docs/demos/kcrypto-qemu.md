<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto QEMU demo (P10): reproduction + viewer narration

Status (final wave, `p10a4-20260930T002951Z`, sealed
`SHA256SUMS` 199/199 OK): host suite 159/159 GREEN
(`host-suite-S19.log`); T01-harness cold boot PASS
(`T01-run.log`); D01/D02/D03/D04/D05/D07/D08 PASS on rerun
(`D01-rerun3.log`, `D02-rerun1.log`, `D03-rerun1.log`,
`D04-rerun2.log`, `D05-rerun1.log`, `D07-rerun1.log`,
`D08-rerun1.log`) with every first failure preserved sealed
(`D01-run.log` FAIL, `D02-run.log` FAIL, `D03-run.log` FAIL,
`D04-run.log` UNSUPPORTED(false), `D05-run.log` FAIL,
`D07-run.log` FAIL, `D08-run.log` FAIL); D06 UNSUPPORTED×2 by
design (`D06-run.log`, `D06-rerun1.log`: X01 provider absent,
no kernel source). Cross-checks: `indep-check.out` 0 failures
over 23 dirs; per-cell `verify --run-dir` verdicts match run
logs. Earlier campaigns: `p10a2-20260930T000653Z` (Task 1 DONE,
D01–D08 NOT_RUN) and `p10a1-20260929T233833Z` (BLOCKED, never
executed). Nothing below claims more than the sealed run logs
and cell receipts.

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

Lane locks and foreign guests: `run` takes every required flock
via repeatable `--lock` — the task lane lock plus the reconciled
common kvm-host flock (`.artifacts/locks/kvm-host.lock`) — holds
them for the whole boot, and records the explicit preexisting-qemu
set in `spawn.json` before launching.
`--refuse-foreign` refuses the launch when that set is non-empty
instead of booting beside foreign guests; without it the set is
recorded and the stop path fails closed on any change. Foreign
processes are never signaled. The strict-exclusivity vs
one-owned-guest wording call is AWAITING-OWNER (O3); the evidence
stands under either reading once clean re-runs exist.

Verification chain (what each checker establishes): `verify`
re-checks the per-cell `SHA256SUMS` contents and re-judges the
recorded receipt checks through the shared-harness reconciler;
`indep-check.py` independently re-parses consoles and cross-checks
receipt/ledger/console/run-log consistency without adjudicating
verdicts; the host suite pins the oracle rules on fixtures. Seal
integrity ultimately rests on `sha256sum -c` over the campaign
`SHA256SUMS`, and every new receipt records its judging
`harness_commit`.

Host gates (no KVM needed):

```sh
python3 -B -m unittest discover -s tests/kcrypto_qemu_demo -v
```

 Budgets: 180 s ordinary cells, 300 s boot cells, 1500 s D08 soak
including cleanup. A timeout, skip, incomplete reference or stale
artifact can never yield PASS.

## Viewer narration (8–12 minute story, qualified per beat)

Evidence root for every beat: sealed campaign
`evidence/kcrypto-demo-qemu/p10a4-20260930T002951Z/`
(`SHA256SUMS` 199/199 OK). Static visual: `timeline.svg` in the
same dir.

1. Available vs selected (D01 — QUALIFIED): `D01-rerun3.log`
   verdict PASS; `cell-D01.json` checks `selected_in_registry`,
   `alloc_split`, `exact_count` all true over a 300/300
   `workload-ledger.jsonl`; `registry.json` lists the providers
   while the single `d01-generic` allocation selects
   `cbc-aes-aesni` (console). Registered-but-unused stays
   "available", never "used". First failures preserved:
   `D01-run.log`, `D01-rerun1.log`, `D01-rerun2.log` (FAIL —
   printk tore JSON ×2).
2. Fresh vs held (D02 — QUALIFIED): `D02-rerun1.log` verdict
   PASS; the fresh `d02-fresh0` allocation selects
   `cbc(ecb(aes-lib))` (console) for 300/300 ledger ops while
   `handles.json` brackets the held `d02-held` `cbc(aes)` handle
   (held → released, never migrated). First failure preserved:
   `D02-run.log` (FAIL — NO-CBC-DRIVER, 0 ops).
3. Real disk (D03 — QUALIFIED): `D03-rerun1.log` verdict PASS;
   `io-ledger.json` records guest-only dm-crypt `demo-d03`
   create/load/resume/remove with exactly 67108864 bytes (64
   MiB) written and fsynced; the io ledger and the product view
   agree on bytes, counted separately from API calls. First
   failure preserved: `D03-run.log` (FAIL — pre-attach burst,
   `product_traffic`).
4. Virtual device / fallback (D04–D06 — STOPS AT DRIVER
   SELECTION): D04 `D04-rerun2.log` verdict PASS but
   `cell-D04.json` pins `device_unknown`, `queue_proof_absent`,
   `no_offload_claim` true and `queue-reference.json` states
   "claim stops at driver selection" (R2 virtqueue adapter
   unavailable); D05 `D05-rerun1.log` verdict PASS with
   `removal-ledger.json` showing `virtio1`/`virtio_crypto`
   before and `[]` after plus recorded fresh traffic
   (`device_after_empty`, `qmp_event_present`); D06
   UNSUPPORTED×2 (`D06-run.log`, `D06-rerun1.log`) — no
   fallback trigger qualified, so no failover is narrated. The
   device stays "unknown"; no queue/binding/offload claim is
   made.
5. Early boot (D07 — QUALIFIED): `D07-rerun1.log` verdict PASS;
   `cell-D07.json` checks `unlock_after_attach` true with
   `dmap_order`, `io_bytes_exact`, `readback_match` true over
   the `demo-d07` dm-crypt unlock (16 MiB write/fsync in
   `io-ledger.json`); everything before attach stays
   UNOBSERVED. First failure preserved: `D07-run.log` (FAIL —
   fail-closed custody: foreign qemu exit).
6. Honest unknowns (D08 — QUALIFIED): `D08-rerun1.log` verdict
   PASS with 15/15 checks in `cell-D08.json` (`loss_visible`,
   `product_saw_head`, `product_missed_tail`, `windows_complete`,
   `stop_under_traffic`); 12000/12000 `workload-ledger.jsonl`
   ops across 20 `soak-windows.json` windows; `stop-receipt.json`
   records the stop under live traffic (window 19, kryprobe
   exit 3). The timeline (`timeline.svg`) labels every arrow
   observed/reference/inferred/unknown with its run ID, and
   replay is labeled replay. First failure preserved:
   `D08-run.log` (FAIL — `marks_ordered` + `product_suffix`).

No firmware-to-userspace completeness claim, no transparent
failover claim, no physical-accelerator claim, no key/credential
material in any output. Product passthrough carries decimal
kernel IPs verbatim (407 `"ip"` fields across the 10 nonzero
p10a4 `product-report.json` files); DEMO: rows are address-free.
Redaction procedure: `kcrypto-qemu-redaction.md` (successor
artifact only — originals preserved, seals untouched; the
redact-fork vs scope-change decision is AWAITING-OWNER as O1).
Narrower, per the seals: no queue/offload claim
for D04 (device "unknown"), no fallback claim for D06
(UNSUPPORTED×2), no pre-attach observation claim for D07, and no
verdict beyond the exact sealed run IDs cited per beat.
