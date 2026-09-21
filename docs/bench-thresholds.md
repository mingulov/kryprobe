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
