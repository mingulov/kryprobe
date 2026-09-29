<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# R1 release ledger (P9/T14 release candidate, repair-2 re-issue)

The release-candidate identity: what was measured, on which
bytes, against which frozen contracts, and where every claim's
receipt lives. Publication is a separate owner action — this
ledger supports review, not release.

This re-issue (repair-2, committed AFTER the repair gates)
supersedes the repair-1 ledger: it splits the residuals
heading into carried/accepted vs T14-pending (P9R2O-N4),
corrects the E-battery NOT_PROVED wording (P9R2O-N2), notes
the rebuild cache scope (P9R2O-N6), and records the repair-2
evidence. Per-finding dispositions live in
`.outbox/kcrypto-t14/REPAIR-1.md` (round 1) and
`.outbox/kcrypto-t14/REPAIR-2.md` (round 2).

## Release identity

- Product: KryProbe kernel-crypto observer (R1 scope:
  api-returns + request-lifecycle profiles on Linux 6.12+
  x86-64; kernel-only product scope, no third-party import).
- Candidate base: `b50ee1a430e71fd470ef5eb817a98e6b8f3f9177`
  (accepted P8 head, `task/kcrypto-t13`).
- Candidate head: `task/kcrypto-t14` repair-2 head (this
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
  digests exactly, `69-release-rebuild-verify.log` —
  with library crates served from cache, not from-clean
  (P9R2O-N6 scope note; build inputs still pinned, all
  three digests reproduced exactly)).
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
suites 272 + 107). Repair-2 re-runs the campaign unit suites
on the pin-gate fix bytes (272 + 110, `73` log; 65–67
transfer by 0-byte Rust delta — no Rust input changed) and
repeats the hardening comparison with the mandatory pin gate
(0 diffs, `72` log + diff). The wave R-wave (11/11 PASS on
identical product sources) stands. Results sealed below.

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
- `rejudge-2/` + `72-rejudge2-verify.log` +
  `72-rejudge2-diff.md`: repair-2 hardening comparison with
  the MANDATORY pin gate (floor fix excluded per owner
  STOP): 0 diffs across 26 sets + 4 diags + 274 legs; no
  verdict moves on present-artifact sealed cells.
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
  (68 repair-1; 73 repair-2 on the pin-gate fix bytes),
  E-battery runs, release build (61) + forced rebuild
  verify (69) + zero-delta (70).
- `final-seal/`: stage manifest + sha256sums + head/tree
  record for the final package (digests re-verified
  identical after the last edit).
- `SHA256SUMS.txt`: top-level seal (self-check OK; 71 log
  repair-1, 75 log repair-2 with preserved seal tooling).

## Carried and accepted (P7/P8)

Explicitly carried accepted verdicts and scope (not
re-proved, not silently dropped):

- Unreferenced-finup residual (deny-leg finup observations
  unqualified; finup-2x outside a kernel-referenced leg).
- Average-only 512 B/call chunking bound (R02; not a
  uniformity proof).
- E08 soak on 7.2.6 NOT_RUN (accepted P7 single-kernel soak;
  7014 re-proved in repair-1).
- X01–X03 / D01–D08: separate P10 demo scope, out of R1.

## T14 results pending owner disposition

T14 outcomes recorded honestly; owner disposition still
required (P9R2O-N4 heading split — the old "Accepted
residuals" heading implied acceptance that hasn't happened):

- Stack sampling NOT_RUN as a standalone mode (no product
  toggle; observables reported instead — see support §P9).
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
- E-battery residuals (P9R2O-N2 wording corrections):
  unpaced e06-7014 NOT_PROVED — failed the Both-generations
  `obs == 100000` check (`verify-cells.py:228`, marked
  "Both generations" at :220), so the pin DOES apply
  post-fence; the accurate statement is that unpaced
  stimulus doesn't qualify post-fence (P7 precedent:
  post-fence unpaced e06-7014b NOT_PROVED-as-designed,
  unsealed); shortfall from `kernel.reserve` = 8032
  (98,397 admitted), counted, receipt explicit (rc 3
  partial).
- Paced e06-726d NOT_PROVED — R0-shaped admit-all outcome
  (admitted == emitted == 100005, unfinished 1) where the
  `refused >= 1` pin failed: the fence did NOT engage
  (refused == 0); a timing race resolved the admit-all way
  (726c refused 3 on the same host/inner); receipt
  explicit, no silent loss.
- Unpaced e07-7014 control NOT_PROVED — the control LOST
  806 events at `kernel.reserve` (1638/1800 admitted),
  failing `control zero loss` (`verify-cells.py:295`).
  E06 is qualified by the paced pair (7014c/726c — one
  post-fence proof per kernel); E07 post-fence proof is
  7.2.6-only (paced e07-726b) — the 7.0.14 reserve-loss
  attribution is unproven on final bytes. No silent loss
  anywhere (receipts explicit, `partial`); no re-runs
  attempted.
- Three attempt-1 cells sampled with the foreign QEMU
  co-resident (disclosed measurement limitation, no re-run).

## Main-drift recheck (ADR-0005)

At handoff: `main` head `d69d88d` (review-remain G10); zero
commits on `main` outside the P8 base history
(`git rev-list --count b50ee1a..main` == 0), i.e. `main` is
an ancestor of the base — no drift into the wave. The wave
branch is 166 commits ahead of `main` (the kcrypto task
stack + the T14 wave + repair-1 + repair-2). Report only —
worker never rebases/merges/pushes/tags; owner integrates.

Explicit integration result for owner review: with zero
drift, integrating this candidate fast-forwards `main` from
`d69d88d` to the repair-2 head (full SHA + tree in the T14
HANDOFF §Repository state). Owner acts; worker states, never
performs.
