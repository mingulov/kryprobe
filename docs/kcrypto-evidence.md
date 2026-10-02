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
kernel operation and not one completed request. Totals and aggregate
rows are read separately. Their difference (`snapshot_gap_unreconciled`,
also retained under the older `ktot_gap` diagnostic name) is not a lost-call
count: an in-flight writer can advance one read after the other. Zero
difference and zero ring drops do not prove an atomic sample. They do not
prove the kernel invoked the sensor for every operation: kernel-side
skips (a hook that never ran, e.g. the G9 cryptd/kworker short-count
signature) are invisible to every product counter.

Accordingly a session without measured loss reports `aggregate_counts`,
`detailed_events`, and `completion` coverage as `Unknown` (reason
counters `uncovered:kernel_delivery_unmeasured` /
`uncovered:completion_unobserved`). Exact-count and absence claims
over such sessions are inconclusive, never clean. Measured loss still
flips its own dimension to `Partial`; real observations still fire
violations — only unprovable absence degrades.

## Checked stop and terminal sampling

Duration, stdin EOF and SIGINT close the backend's owned links, join its
collector, decode every forwarded tail record once, and take one terminal
map sample with fresh who joins. Cumulative terminal rows replace running
rows. The interval starts before attachment and ends after the terminal
map reads; contradictory nonzero timestamps fail the capture.

This remains a **non-atomic sample**. Link close, an empty ring, repeated
stable reads and userspace barriers do not establish a kernel writer fence.
`uncovered:aggregate_snapshot_not_quiescent` records that limit. Exact
reconciliation requires a later versioned kernel control contract.

The backend owns the measured ring and who drop indicators; shared transport
owns measured queue refusals. Ring 7 and queue 3 therefore remain 7 and 3.
The ring/who indicators are existing capped u8 counters, not unbounded exact
loss totals. A bounded final ring sweep also reports `terminal_backlog_bytes`
and `terminal_busy`; unread bytes are not missing-record counts. Worker panic,
poll/map/topology/decode failure or missing terminal receipt fails the capture
with any known partial drain statistics; panic never supplies clean zeros.

Ordinary JSON retains raw row/total measurements, diagnostic counters and
consistency reasons. Frozen event-v0 JSONL and replay preserve conservative
Unknown/Partial status but cannot preserve new counter names or the exact
sample-difference magnitude. A difference never becomes `omitted_count`.
`session_end.final_barrier = validated` attests completed host output only,
not atomic maps or finished kernel writers. `missing_final_barrier` means an
actually expected host marker failed, not that this profile lacks a kernel
quiescence protocol. Zero counters never qualify exact counts or absence.

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
- Non-atomic aggregate measurements and checked transport-loss accounting.
- Policy violations on real observations; inconclusive (never clean)
  absence/exact-count verdicts.

Out of scope: request completion, per-request latency, driver-body
entry proof, exact missing-operation counts, and any claim that a
clean ring implies complete kernel delivery.

## Hash API routing differs between kernels

The hash hooks are `crypto_ahash_digest`, `crypto_shash_digest`, and
`crypto_shash_finup`. Separate update/final APIs are not hooked.
On the observed 6.12.111 SHA-256/SHA-512 AF_ALG route, a multipart
message ending with an empty send uses those separate update/final
APIs and produces no finup observation. On 7.2.6, shash update/final
wrappers route through finup instead. A zero finup count therefore
does not establish that no multipart hashing occurred.

Finup byte counts sum the `len` argument of observed finup calls;
they do not necessarily include input handled by an unhooked update.
Kernel release strings alone do not establish this call route.

The exact finup tests use a separate prepared-operation control: feed a
32-byte prefix before attachment, retain that operation, then clone and
finalize it with a 16-byte chunk for each measured digest. Independent
worker-only traces on 6.12.111 and 7.2.6 qualify one shash finup per clone
for the tested shash-backed SHA-256/SHA-512 routes. Digest goldens check
the full 48-byte message; observed finup bytes remain 16 per call. Native
ahash providers are not covered by that shash-route expectation.
