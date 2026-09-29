<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# R1 release ledger (P9/T14 release candidate, repair-1 re-issue)

The release-candidate identity: what was measured, on which
bytes, against which frozen contracts, and where every claim's
receipt lives. Publication is a separate owner action — this
ledger supports review, not release.

This re-issue (repair-1, committed AFTER the repair gates)
supersedes the wave ledger: it corrects the byte-identity
wording (P9R1O-N4), the pressure claim (P9R1O-N3), the
residuals list and ahead-count (P9R1O-N6), and records the
repair-1 evidence. Per-finding dispositions live in
`.outbox/kcrypto-t14/REPAIR-1.md`.

## Release identity

- Product: KryProbe kernel-crypto observer (R1 scope:
  api-returns + request-lifecycle profiles on Linux 6.12+
  x86-64; kernel-only product scope, no third-party import).
- Candidate base: `b50ee1a430e71fd470ef5eb817a98e6b8f3f9177`
  (accepted P8 head, `task/kcrypto-t13`).
- Candidate head: `task/kcrypto-t14` repair-1 head (this
  commit; full SHA + tree in the T14 HANDOFF §Repository
  state — BPF/ABI/wire/event-v0 frozen, measurement +
  packaging + docs only; zero SOURCE delta under `crates/`,
  `xtask/`, `packaging/` vs base,
  `70-zero-delta-repair1.log`).
- Binary: kryprobe 0.1.0, sha256
  `c9ae31bd5517700404392311d68643aede4936ae47c41db39caef8800fe24ec2`
  (pinned release build, `KRYPROBE_REQUIRE_PINS=1`,
  manifest v2, `pins_enforced: true`).
- BPF objects: kcrypto.bpf.o
  `c76fd83f532869b6d86f7189af0d4575d78b27137f5b77873b3043fe9eba97f5`,
  kcrypto-lifecycle.bpf.o
  `7244932d0c8828919770b32ba1555b1a74eccd674de326a6173d062dd0f150cb`
  (digests baked + enforced; REBUILT from the identical
  sources — the wave text's "byte-identical to the P8-base
  build" was wrong (P9R1O-N4): sources are identical,
  builds are rebuilt; the forced rebuild reproduces these
  digests exactly, `69-release-rebuild-verify.log`).
- Fixture modules (test-only): 7.0.14
  `6004d75d09c056e5d6cd5d3645b17b0fb32a104df8905cb72f9ab00c8ddd517d`,
  7.2.6
  `e6d4dfdad4cc43e86910d1d95d5d8dbce398ff666deaacf32ac2595fa3dc2df1`.
- Frozen contracts: performance budgets
  (`docs/bench-thresholds.md` P9, frozen before sampling);
  perf manifest `tests/kcrypto_perf/cells.json` (sha256
  `5a9d6dbf4bb8cadd0ee32935de09e49b8b0dae886a42dc158363eb9589ae7320`,
  frozen before the first sampling boot); R-wave manifest
  `tests/kcrypto_campaign/cells.json` (sha256
  `8d663eb599382fd6a8230a1b7ec0181110ccbe9055e10499039700079dca8cb2`,
  carried unchanged from P8); T12 E-battery oracle
  `evidence/kcrypto-t14/ebat/verify-cells.py` (byte-identical
  to the sealed P7 oracle) + retargeted runner (diff in
  `63-ebat-oracle.log`); test/evidence contract
  (`planning/2026-09-24-krypto-test-matrix.md`); design
  constraints C01–C18
  (`planning/2026-09-24-kcrypto-continuation-design.md`).

## Phase acceptance carried forward

| Phase | Accepted at | Record |
|---|---|---|
| P1 (T07) | `7ec080b` | T07 done record |
| P2 envelope | `8025335` + packet-r4 | P2 record |
| P3 (T08) | `75f0758` | P3 record |
| P4 (T09) | `e52c52e` | P4 record |
| P5 (T10) | `88757d6` | P5 record |
| P6 (T11) | `4861b0a` | P6 record |
| P7 (T12) | `0f43994` | P7 record (E08/7.2.6 NOT_RUN carried) |
| P8 (T13) | `b50ee1a` | P8 record, 11/11 cells PASS |

Historical passes are carried verdicts, not new evidence.
Repair-1 re-runs on the final bytes: the full P7 E-battery
(19/22 PROVED + 3 analyzed NOT_PROVED, `63-ebat-oracle.log`),
the root canary lanes (canary + lifecycle + attach, all
executed as root in owned guests), the real-consumer install
path (installer rc 0 with live cap grant + live-traffic
report), and the host gates (`cargo xtask check` 1482/0,
`cargo xtask test bpf` 231/0, `verify generated` 8/0,
suites 272 + 107). The wave R-wave (11/11 PASS on identical
product sources) stands. Results sealed below.

## P9 evidence map (workspace `evidence/kcrypto-t14/`)

- `cells/`: 26 sealed pair-set cells + 4 diagnostic cells
  (per-leg driver ledgers, product reports, sampler logs,
  quiet legs, spawn/stop receipts, per-cell SHA256SUMS).
- `cells/verdicts/` + `campaign.json`: frozen-rule judges
  output (leg/pair/set verdicts, budget B1/B2, locks proof).
- `perf-report.md`: campaign report (ratios, envelopes,
  observer metrics, limitations; repair-1 corrections for
  the bulk-control interpretation, floor defect, lag/
  occupancy/stop/host gaps, co-resident-VM + in-place-
  rewrite disclosures).
- `rcells/`: 11 sealed R-wave re-run cells (R01–R04 on the
  wave bytes; product sources identical to repair-1 final)
  + campaign verdict log.
- `rejudge-1/` + `60-rejudge-verify.log` +
  `60-rejudge-diff.md`: repair-1 differential re-judge with
  the hardened gates (floor fix excluded per owner STOP):
  0 diffs across 26 sets + 4 diags + 274 legs.
- `ebat/`: 25 sealed repair-1 cells (22 E-battery + 2
  canary + 1 install) + the oracle, adapted runner (diff
  recorded), staging/batch/judge scripts;
  `62-ebat-batch.log` (runs) + `63-ebat-oracle.log`
  (judgments) + `64-ebat-seals.log` (per-cell seals).
- `claim-manifest.md` + `claims/`: C01–C18 claim manifest with
  per-claim receipts (repair-1 re-proof: C04/C08/C09/C12/
  C14/C16/C18; re-stated C02/C03/C05/C07/C15/C17).
- Gate logs: `cargo xtask check` (65), `cargo xtask test bpf`
  (66, incl. post-lane object hashes),
  `cargo xtask verify generated` (67), campaign unit suites
  (68), E-battery runs, release build (61) + forced rebuild
  verify (69) + zero-delta (70).
- `final-seal/`: stage manifest + sha256sums + head/tree
  record for the final package (digests re-verified
  identical after the last edit).
- `SHA256SUMS.txt`: top-level seal (self-check OK, 71 log).

## Accepted residuals and NOT_RUN lanes

Carried explicitly (not re-proved, not silently dropped):

- Unreferenced-finup residual (deny-leg finup observations
  unqualified; finup-2x outside a kernel-referenced leg).
- Average-only 512 B/call chunking bound (R02; not a
  uniformity proof).
- E08 soak on 7.2.6 NOT_RUN (accepted P7 single-kernel soak;
  7014 re-proved in repair-1).
- Stack sampling NOT_RUN as a standalone mode (no product
  toggle; observables reported instead — see support §P9).
- X01–X03 / D01–D08: separate P10 demo scope, out of R1.
- 4 KiB aggregate budgets FAIL on both kernels (decisive,
  10/10 pairs miss both budgets; ~18–20% throughput overhead
  at 41–47k ops/s — the RC does not meet the proposed
  ≤5%/≤10% targets).
- `perf-P-1M-agg-7014` INCONCLUSIVE (spread 0.84–1.13, 2/5
  inside; a noisy interval stays inconclusive).
- All 13 det sets INVALID (0/5 valid: 100k truncation at
  28–44x offered + counted tombstone loss below cap); both
  floor sets INVALID (0/5 valid: `destroy_skip == 3` vs the
  judge-applied flat pin — harness defect P9R1O-N2 recorded,
  code fixed, re-judge pending owner authority);
  diag-stack INVALID (one paced leg missed pace). Item-2
  disposition (narrow vs new wave) is AWAITING-OWNER.
- Observer gaps: drain lag NOT measured (no numerical
  bound); map/state occupancy levels NOT reported; stop
  cost NOT measured; host load/governor/CPU-features/
  tracing NOT recorded in sealed receipts (all disclosed in
  `perf-report.md`; receipt generator enriched for future
  runs).
- E-battery residuals: unpaced e06-7014 NOT_PROVED (98,397
  retained vs R0 pin 100,000 — counted ring-reserve shed
  under the 4 s hammer; R0 pin inapplicable to the fenced
  product); paced e06-726d NOT_PROVED (admit-all boundary
  race, refused==0 — timing-shaped pin miss); unpaced
  e07-7014 control NOT_PROVED (1638/1800 — same counted
  burst-shedding class); E06 qualified by the paced pair,
  E07 by the paced leg. No silent loss anywhere (receipts
  explicit); no re-runs attempted.
- Three attempt-1 cells sampled with the foreign QEMU
  co-resident (disclosed measurement limitation, no re-run).

## Main-drift recheck (ADR-0005)

At handoff: `main` head `d69d88d` (review-remain G10); zero
commits on `main` outside the P8 base history
(`git rev-list --count b50ee1a..main` == 0), i.e. `main` is
an ancestor of the base — no drift into the wave. The wave
branch is 163 commits ahead of `main` (the kcrypto task
stack + the T14 wave + repair-1). Report only — worker never
rebases/merges/pushes/tags; owner integrates.

Explicit integration result for owner review: with zero
drift, integrating this candidate fast-forwards `main` from
`d69d88d` to the repair-1 head (full SHA + tree in the T14
HANDOFF §Repository state). Owner acts; worker states, never
performs.
