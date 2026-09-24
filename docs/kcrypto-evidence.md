<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto evidence semantics (api-returns profile)

KryProbe v0.1 observes the kernel crypto API through a single-edge
fexit sensor: it sees API-invocation returns. Every row carries
`capture_profile: "api-returns"`; counted rows additionally carry
`count_unit: "api_invocation_return"` and
`completion_coverage: "unobserved"`. This note states what that does
and does not prove.

## What one count means

One count is one observed API-invocation return — not one delivered
kernel operation and not one completed request. Totals reconcile
against aggregate rows internally (`ktot_gap`), but a zero gap with
zero ring drops proves product-side reconciliation only. It does not
prove the kernel invoked the sensor for every operation: kernel-side
skips (a hook that never ran, e.g. the G9 cryptd/kworker short-count
signature) are invisible to every product counter.

Accordingly a reconciled session reports `aggregate_counts`,
`detailed_events`, and `completion` coverage as `Unknown` (reason
counters `uncovered:kernel_delivery_unmeasured` /
`uncovered:completion_unobserved`). Exact-count and absence claims
over such sessions are inconclusive, never clean. Measured loss still
flips its own dimension to `Partial`; real observations still fire
violations — only unprovable absence degrades.

## Status is representative, errnos are exact only on who rows

Aggregate and totals rows carry a canonical representative status
(`status_canonical: true`): ok/queued map to 0/`-EINPROGRESS`, every
error class maps to `-EIO`, whatever the true kernel errno was. The
representative status cannot satisfy a predicate that requires the
exact original errno; aggregate rows carry no `native_code`.

Exact native errnos appear only as `who` `first_errno`, rendered when
the value is a real failure (negative, neither `-EINPROGRESS` nor
`-EBUSY`). A row for `ENOKEY` carries the selected driver but states
no driver-body execution: selection is observed, entry is unproven,
and zero successful work is counted.

## Completion and latency are unobserved

Terminal request completion is not observed: no callback, fence, or
terminal-state edge exists in this profile. Per-invocation latency is
likewise unavailable — `lat` passes through verbatim (the BPF writes
zeros; no durations exist) and nothing derives microseconds from it.
Absence of a latency claim renders as unavailable, never as zero.

## G9 and the older bounded tests

The bounded kworker-miss and drain tests document a residual
short-count risk with explicit bounds; they do not claim a kernel
fix and they do not compute an exact missing count from static
inspection. A passing bounded test means "shortfall, if any, is
within the stated bound", not "delivery was complete".

## Supported observation boundary (v0.1)

- API selection and return classes per (family, op, result, context).
- Caller identity markers (who rows) with params and first failure.
- Internal counter reconciliation and transport-loss accounting.
- Policy violations on real observations; inconclusive (never clean)
  absence/exact-count verdicts.

Out of scope: request completion, per-request latency, driver-body
entry proof, exact missing-operation counts, and any claim that a
clean ring implies complete kernel delivery.
