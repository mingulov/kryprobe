<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# R1 release ledger (P9/T14 release candidate)

The release-candidate identity: what was measured, on which
bytes, against which frozen contracts, and where every claim's
receipt lives. Publication is a separate owner action — this
ledger supports review, not release.

## Release identity

- Product: KryProbe kernel-crypto observer (R1 scope:
  api-returns + request-lifecycle profiles on Linux 6.12+
  x86-64; kernel-only product scope, no third-party import).
- Candidate base: `b50ee1a430e71fd470ef5eb817a98e6b8f3f9177`
  (accepted P8 head, `task/kcrypto-t13`).
- Candidate head: `task/kcrypto-t14` wave head (this commit;
  full SHA + tree in the T14 HANDOFF §Repository state —
  BPF/ABI/wire/event-v0 frozen, measurement + packaging +
  docs only; zero delta under `crates/`, `xtask/`,
  `packaging/` vs base).
- Binary: kryprobe 0.1.0, sha256
  `c9ae31bd5517700404392311d68643aede4936ae47c41db39caef8800fe24ec2`
  (pinned release build, `KRYPROBE_REQUIRE_PINS=1`,
  manifest v2, `pins_enforced: true`).
- BPF objects: kcrypto.bpf.o
  `c76fd83f532869b6d86f7189af0d4575d78b27137f5b77873b3043fe9eba97f5`,
  kcrypto-lifecycle.bpf.o
  `7244932d0c8828919770b32ba1555b1a74eccd674de326a6173d062dd0f150cb`
  (digests baked + enforced; byte-identical to the P8-base
  build — docs-only wave).
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
  carried unchanged from P8); test/evidence contract
  (`planning/2026-09-24-kcrypto-test-matrix.md`); design
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

Historical passes are carried verdicts, not new evidence; P9
re-runs the full gate set on the final bytes (host, artifact,
supported/floor, real-consumer, privacy, required pressure)
and seals the results below.

## P9 evidence map (workspace `evidence/kcrypto-t14/`)

- `cells/`: 26 sealed pair-set cells + 4 diagnostic cells
  (per-leg driver ledgers, product reports, sampler logs,
  quiet legs, spawn/stop receipts, per-cell SHA256SUMS).
- `cells/verdicts/` + `campaign.json`: frozen-rule judges
  output (leg/pair/set verdicts, budget B1/B2, locks proof).
- `perf-report.md`: campaign report (ratios, envelopes,
  observer metrics, limitations).
- `rcells/`: 11 sealed R-wave re-run cells (R01–R04 on the
  final bytes) + campaign verdict log.
- `claim-manifest.md` + `claims/`: C01–C18 claim manifest with
  per-claim receipts.
- Gate logs: `cargo xtask check`, `cargo xtask test bpf`,
  `cargo xtask verify generated`, campaign unit suites,
  R-wave runs, release build.
- `final-seal/`: stage manifest + sha256sums + head/tree
  record for the final package.
- `SHA256SUMS.txt`: top-level seal (self-check OK).

## Accepted residuals and NOT_RUN lanes

Carried explicitly (not re-proved, not silently dropped):

- Unreferenced-finup residual (deny-leg finup observations
  unqualified; finup-2x outside a kernel-referenced leg).
- Average-only 512 B/call chunking bound (R02; not a
  uniformity proof).
- E08 soak on 7.2.6 NOT_RUN (accepted P7 single-kernel soak).
- Stack sampling NOT_RUN as a standalone mode (no product
  toggle; observables reported instead — see support §P9).
- X01–X03 / D01–D08: separate P10 demo scope, out of R1.
- Run-to-run INCONCLUSIVE sets, if any, stay inconclusive
  (listed in the campaign report, never upgraded).

## Main-drift recheck (ADR-0005)

At handoff: `main` head `d69d88d` (review-remain G10); zero
commits on `main` outside the P8 base history
(`git rev-list --count b50ee1a..main` == 0), i.e. `main` is
an ancestor of the base — no drift into the wave. The wave
branch is 157 commits ahead of `main` (the kcrypto task
stack). Report only — worker never rebases/merges/pushes/
tags; owner integrates.
