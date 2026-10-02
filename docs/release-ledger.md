<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v0.1.0 release ledger and accepted P9/T14 evidence

The release-candidate identity: what was measured, on which
bytes, against which frozen contracts, and where every claim's
receipt lives. Publication is a separate owner action — this
ledger supports review, not release. The initial public release has the
limited scope in [v0.1.0 release notes](releases/v0.1.0.md); R1 remains open.

## First-release decisions and corrected floor results (2026-09-30)

The owner has resolved all five release-policy choices:

- O1: original stack addresses may remain in the two completed disposable
  demo campaigns, p10a4/p10a7. Their original bytes and seals are preserved.
- O2: boot-demo scope is initramfs-local, with three fresh boots and the
  late/broken-observer controls. Continuous `switch_root` capture is deferred.
- Item-2: accept measured performance limits for the first release; full
  qualification remains unmet, with 7.x budget FAILs and detail INVALIDs intact.
- Floor: one authorized corrected offline evaluation is complete. Both
  Linux 6.12 sets now have ENVELOPE verdicts and 5/5 valid pairs. Throughput/
  workload-p99 medians are 0.739196/1.394026 (4 KiB) and
  0.889887/1.243607 (1 MiB); these are unbudgeted operating data, not PASSes.
  All measured values, the 24 other sets and all four diagnostics are unchanged.
  The whole campaign remains INVALID with 14 reasons.
- O3: future QEMU demo runs use strict exclusivity, both locks and
  `--refuse-foreign`; they wait/refuse without stopping unrelated guests.

The floor successor is
`evidence/kcrypto-t14-floor-rejudge/20260930T111512Z/`, sealed 68/68.
Its `RESULTS.md` and `PROVENANCE.json` bind the original T14 seal; it
supplements the original floor INVALIDs without editing their history.
Seal digests for the four evidence trees are in the release notes.
The source chain is main `865301b` -> accepted T14 `d7cb048` ->
accepted demo `a3987e7` -> release documentation/CI preparation.
Commit identities are post-2026-09-30 author-name rewrite; the
content-identical pre-rewrite SHAs remain in the private acceptance records.
The runtime source and frozen contracts are unchanged by that preparation.

## Historical T14 repair-3 record

This re-issue (repair-3, committed AFTER the repair gates)
supersedes the repair-2 ledger: it records the repair-3
evidence (the `"none"`-pin gate restriction, the C18 cache
wording correction, the rejudge-3 hardening comparison, the
77 suites, the 78 re-seal). Per-finding dispositions live in
`.outbox/kcrypto-t14/REPAIR-1.md` (round 1),
`.outbox/kcrypto-t14/REPAIR-2.md` (round 2), and
`.outbox/kcrypto-t14/REPAIR-3.md` (round 3).

## Release identity

- Product: KryProbe kernel-crypto observer (R1 scope:
  api-returns + request-lifecycle profiles on Linux 6.12+
  x86-64; kernel-only product scope, no third-party import).
- Candidate base: `648c4d1af373a7d8b7489a5b049e2836c6cb6646`
  (accepted P8 head, `task/kcrypto-t13`).
- Candidate head: `d7cb04826525d3e1696c3a58d4932c98801b8580`
  (`task/kcrypto-t14` repair-3; full SHA + tree in the T14 HANDOFF §Repository
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
| P1 (T07) | `d522476` | T07 done record |
| P2 envelope | `241106f` + packet-r4 | P2 record |
| P3 (T08) | `319e983` | P3 record |
| P4 (T09) | `58081d6` | P4 record |
| P5 (T10) | `bee0b6a` | P5 record |
| P6 (T11) | `f9e9066` | P6 record |
| P7 (T12) | `8d23cf3` | P7 record (E08/7.2.6 NOT_RUN carried) |
| P8 (T13) | `648c4d1` | P8 record, 11/11 cells PASS |

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
(0 diffs, `72` log + diff). Repair-3 re-runs the suites on
the `"none"`-pin restriction bytes (272 + 113, `77` log;
65–67 transfer again by 0-byte Rust delta) and repeats the
hardening comparison once more (0 diffs, `76` log + diff).
The wave R-wave (11/11 PASS on identical product sources)
stands. Results sealed below.

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
- `rejudge-3/` + `76-rejudge3-verify.log` +
  `76-rejudge3-diff.md`: repair-3 hardening comparison with
  the `"none"`-pin restriction (floor fix excluded per owner
  STOP): 0 diffs across 26 sets + 4 diags + 274 legs; no
  verdict moves (sealed `"none"` occurs only for
  `kcrypto_fixture.ko`).
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
  (68 repair-1; 73 repair-2 on the pin-gate fix bytes; 77
  repair-3 on the `"none"`-pin fix bytes),
  E-battery runs, release build (61) + forced rebuild
  verify (69) + zero-delta (70).
- `final-seal/`: stage manifest + sha256sums + head/tree
  record for the final package (digests re-verified
  identical after the last edit).
- `SHA256SUMS.txt`: top-level seal (self-check OK; 71 log
  repair-1, 75 log repair-2, 78 log repair-3 with preserved
  seal tooling).

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

## R1 1 MiB aggregate follow-up

A new `perf-P-1M-agg-7014` wave on 2026-10-01 at
`0c16410bf064fb67cc8fbb7b30820aa473b5e041` passed the frozen budgets:
median throughput ratio 0.982 and workload-p99 ratio 1.015, with all
5 pairs inside both budgets. This PASS applies only to that R1 sample;
it does not re-grade P9 or qualify v0.1.0 release bytes or other sets.
Retained private-workspace report:
`evidence/kcrypto-r1-perf/perf-report.md`; original cell `SHA256SUMS`
digest: `611d2fc23685639cd216f99015ba09a6796f6bd6218024a2ccb792044f27a317`.

## T14 results accepted as first-release limitations

The owner accepted the following limits for v0.1.0 on 2026-09-30.
The floor correction above is the sole separately derived verdict change.
The original records below remain available without rewriting their bytes:

- Stack sampling NOT_RUN as a standalone mode (no product
  toggle; observables reported instead — see support §P9).
- 4 KiB aggregate budgets FAIL on both kernels (decisive,
  10/10 pairs miss both budgets; ~18–20% throughput overhead
  at 41–47k ops/s — the RC does not meet the proposed
  ≤5%/≤10% targets).
- `perf-P-1M-agg-7014` INCONCLUSIVE (spread 0.84–1.13, 2/5
  inside; a noisy interval stays inconclusive).
- All 13 det sets INVALID (0/5 valid: 100k truncation at
  28–44x offered + counted tombstone loss below cap).
  Both floor sets were originally INVALID (0/5 valid because
  the checker applied a flat destroy-skip pin to the nested route);
  the authorized correction above gives ENVELOPE, 5/5 each.
  Diag-stack remains INVALID (one paced leg missed pace).
  Full item-2 qualification and a new sampling wave are deferred.
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

## Historical main-drift recheck at T14 handoff (ADR-0005)

At handoff: `main` head `865301b` (review-remain G10); zero
commits on `main` outside the P8 base history
(`git rev-list --count 648c4d1..main` == 0), i.e. `main` is
an ancestor of the base — no drift into the wave. The wave
branch is 166 commits ahead of `main` (the kcrypto task
stack + the T14 wave + repair-1 + repair-2). Report only —
worker never rebases/merges/pushes/tags; owner integrates.

That handoff proposed a fast-forward from `865301b`; it did not
perform one. The current release preparation includes the accepted
repair-3 and demo heads listed above, plus the owner decisions.
The coordinator rechecks main immediately before a fast-forward and
records the actual integrated SHA/tree. Publication remains an owner action.
