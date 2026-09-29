<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Bench regression gates (4B-L1)

`cargo xtask bench` stays record-never-assert by design: the command
prints receipts (or `DENIED <stage>`) and never fails on values.
The regression gate lives one layer up, on the privileged runner
(4B-H2): it stores one `bench --json` receipt per run and alerts on
threshold drift. This page is the threshold spec the runner
implements. Baselines are per-runner (hardware differs); each
runner seeds them from its first 10 green runs.

## Receipt store

Per run, the runner archives the full `bench --json` document as
`<evidence>/bench/<UTC-date>-<tree-sha>.json` and appends one row
per suite to a `bench-history.ndjson` beside it:

```text
{"date": str, "sha": str, "machine": {...}, "suite": str,
 "status": "ok"|"denied", "stage": str?, "detail": {...}}
```

Denied rows never alert on values (there are none); a suite that
flips ok→denied across runs alerts as an environment regression
(the lane lost its objects, fixtures, or privilege).

## Thresholds

| Suite | Metric (`detail` key) | Alert rule |
|---|---|---|
| `attach` | `p99_ms` | +50% over the rolling median of the last 10 ok runs (C1-class attach regression) |
| `attach` | `median_ms` | informational (recorded, no alert) |
| `drain` | `loss` | `> 0` alerts immediately (C1-class drain loss) |
| `drain` | `median_events_per_s` | −50% under the rolling median of the last 10 ok runs |
| `elf` | `still_fastest` | `false` alerts (loader-path order flip; the parse hot path changed shape) |
| `elf` | `fixtures` medians | informational per-cell medians (ms) for triage |
| `e2e` | `median_ms` | +3x over the rolling median of the last 10 ok runs (full-pipeline drift) |

Rolling medians use ok-status rows only; the first 10 ok runs per
runner seed the baseline and never alert.

## Selftest tripwire

`scripts/sudo-lane.sh` runs `selftest bpf --calls 20000`: the lane
alerts unless the output reads `reconcile: clean` (exit 0).
`reconcile: partial` (exit 3) and `Denied{stage}` (exit 4) are
regressions once the runner is green — the lane's kernel surface
changed or broke.

## Status

Specified, not yet wired: the privileged runner (4B-H2) does not
exist, so no receipts are stored and no alerts fire. The attach
and drain suites read `DENIED` without privilege — their
thresholds activate on the runner's first green privileged run.

## P9 frozen performance budgets (T14 release candidate)

Frozen 2026-09-29, before the first T14 sampling boot (preflight
mapping runs used a throwaway prototype driver and are not
samples). These budgets are the P9 release decision recorded in
advance; they are never moved after results. The campaign
manifest (`tests/kcrypto_perf/cells.json`) carries the frozen
cell list, equivalence relations, and validity rules; this page
carries the budgets and verdict rules.

### Budgets

On every QUALIFIED 4 KiB / 1 MiB aggregate-mode pair-set:

- B1 (throughput): median disabled→aggregation throughput ratio
  ≥ 0.95 (at most 5% median throughput regression).
- B2 (tail latency): median disabled→aggregation workload-p99
  ratio ≤ 1.10 (at most 10% median workload-p99 regression),
  where workload latency is the driver's per-op roundtrip
  (submit→terminal), never the product's unpopulated `lat`
  array and never an unobserved async percentile.

A pair-set is QUALIFIED only if: ≥5 valid alternating pairs;
every observed leg reconciles exactly with its driver ledger
(per the manifest's pinned per-kernel equivalence: 7.x flat
1 call per op per direction, 6.12 floor nested 1:1 outer+inner);
loss sites 0–4 and spares are 0 with `ktot_gap`, `ring_drops`,
and `overflow_identities` all 0; capture rc ∈ {0,3}; driver
rc 0 with no timeout; the boot quiet leg shows 0 calls. Any
measured rate with unexplained loss is outside the qualified
envelope regardless of overhead.

### Verdict rule (frozen)

Per pair-set, with pair ratios in preserved run order:

- PASS if the median pair ratio is inside the budget AND at
  least 4 of 5 pairs are inside the budget.
- FAIL if the median is outside the budget AND at least 4 of
  5 pairs are outside.
- INCONCLUSIVE otherwise (spread too wide for five samples —
  reported, never upgraded by re-analysis).

Outliers are preserved and reported; they are never dropped to
reach a verdict. Spare pairs (up to 8 attempted per set) continue
the alternating order in the same boot; all legs are sealed.

### Non-budget modes (envelopes, not ratios)

64 B, high-rate AEAD, deliberately-async, full-details
(request-lifecycle), and paced-qualification sets publish
measured operating envelopes and rate limits; no budget applies.
A details-mode leg that truncates at the 100,000-observation
bound is an envelope data point (explicit Partial, counted
loss), never a valid overhead pair leg. Stack sampling has no
standalone product toggle (R1 stacks are first-seen-only
attribution inside api-returns): it is NOT_RUN as a mode, with
stack-attribution observables reported from the aggregation
cells plus one separately-named many-submitter diagnostic probe.
Attached-idle is an observer-footprint leg (session live,
workload idle), not a workload pair.
