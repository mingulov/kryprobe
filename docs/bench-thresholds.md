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

## R1 frozen performance budgets (FROZEN 2026-10-01T14:27:42Z — no edits after first R1 sampling boot)

R1 re-tests the observer against the UNCHANGED P9 budgets: B1
(median throughput ratio ≥ 0.95) and B2 (median workload-p99
ratio ≤ 1.10), same verdict rule (median plus ≥80% of pairs
inside), same QUALIFIED pair-set conditions. No budget is
moved; the bar did not move.

Observer delta vs P9: NONE on the probe path. The BPF objects
are bit-identical to the P9-qualified build; the H1
per-alg identity-cache experiment measured neutral on host
A/B (0.807–0.826 vs replicated baseline 0.800–0.846) and was
reverted. R1 product changes are capture-side only:
machine-readable observer telemetry (drain lag, occupancy,
stop spans) on stderr, which cannot perturb the driver
workload. The 4K optimization leg is therefore routed to the
owner per stop conditions with a replicated host floor
(0.80–0.85); the frozen 4K budgets stand and the wave judges
them honestly.

Pre-pinned R1 rule changes (all frozen in advance, never
post-hoc):

- Detail validity is tombstone-tolerant: a detail leg is valid
  iff it does not truncate, obs == expected, emitted ==
  admitted, unfinished == 0 (sync), driver rc 0 with no
  timeout, pace gate held (paced legs), and the receipt loss
  dict carries ONLY `adapter.tombstone_evictions` (counts
  reported per leg via `tolerated`, unbounded). Any other loss
  key invalidates. (P9 invited this rule in advance;
  `scripts/kcrypto_perf/validity.py`
  `TOLERATED_DETAIL_LOSS` implements it.)
- Floor `predrop_destroy_skip == 3` is pinned in the manifest
  (P9 sealed 10/10 + floor-rejudge verified;
  `FLOOR_DESTROY_PIN`). Floor sets stay ENVELOPE (non-budget).
- Bulk reference legs extend to 726/612 agg sets
  (`hosts_bulk`), and the repaired `roundtrip_bulk` fixture
  (no clock reads) finally quantifies timestamping cost,
  unquantified in P9 (P9R1A-N8).

R1 wave scope (targeted; the 26-set manifest stays the frozen
campaign definition): 8 sets — `perf-P-4K-agg-7014`,
`perf-P-4K-agg-726` (budgeted FAIL floor + timestamping cost +
bulk control), `perf-P-1M-agg-7014` (INCONCLUSIVE clean
re-run), `perf-P-1M-det-7014/726` + `perf-P-64-det-paced-7014`
+ `perf-P-4K-det-paced-7014` + `perf-P-AEAD-det-paced-7014`
(below-cap det under the tolerant rule; P9 reconciled them
exactly with tombstone-only loss). The other 18 sets are
NOT_RUN: flat fast-det truncates 5–44x by construction and
async-det sheds/misses the pace gate by construction (P9
INVALIDs stand on unchanged code+shape); `perf-P-1M-agg-726`
PASS stands (observer + ledger fixture unchanged);
64/AEAD/ASYNC-agg reference ratios stand (726 row-cost control
comes from the 4K-726 bulk legs, same kernel + rate regime);
612 floor verdicts stand (re-judge executed); diagnostics
unchanged.

The R1 judge tree (`scripts/` at the freeze commit) is frozen
with the manifest (SHA recorded in the freeze receipt); T14
reproduction keeps its own PINNED judge and is unaffected.
