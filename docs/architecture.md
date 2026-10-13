<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Architecture (3B-M5)

System overview: crates, the two session paths, and the BPF
map/data-flow. Details live in rustdoc; this file is the map.

## Crate map

```text
 CLI (kryprobe-cli: args, watch/report/check, selftests)
  │   uses all of: core, policy, privilege, report, abi
  ▼
 report (JSONL writer/validator/renderer, live tables, policy ←┐)
 policy (YAML rules, glob match, VIOLATION/CLEAN/INCONCLUSIVE)  │ dev-only
 privilege (BPF load/attach/drain, kcrypto decode, token lane)  │ testkit
 core (Backend trait, driver, session, evidence, coverage) ─────┘ (fixtures,
 abi (wire enums, event headers, kcrypto map structs — shared     goldens)
      with BPF: both BPF crates depend only on abi + aya-ebpf)
```

Dependency rules: `core` never depends on `report` (the live JSONL
export reads core types; the reverse edge would invert the layering
— see 1B-M1); production code never depends on `testkit`
(enforced by the `depguard` xtask test); privilege is the only
crate that touches the kernel directly (ADR-0002).

Workload enrichment is a standalone binary outside the layering
above:

```text
 workload-helper (stdio metadata snapshot responder, core-only;
   launched by privilege under a non-root principal)
```

It reads one snapshot request on stdin, writes one response on
stdout, and never parses metadata as root nor guesses from
environment variables (ADR-0008 §(h)). Its associations feed the
workload-report-v1 views rendered from `core::workload`'s pure
model (ADR-0008 §§(g),(i)).

## The two session paths (split blessed: ADR-0007)

Two drivers run the `Backend` lifecycle, and they are not the same
code — the split is deliberate and will not converge:

- `BackendDriver` (`core/src/backend/driver.rs`): the registry
  driver — detect → plan → configure → decode → finalize over
  owned backends, with skip receipts and exactly-once shared-loss
  feeds. Used by `backends` liveness, the driver lane test, and
  unit/integration tests.
- `drive_session` / `drive_lifecycle_session` (`cli/src/live.rs`):
  the live drivers — sensor reads (tick loop for aggregates,
  sustained drain for lifecycle) → decode → finalize once,
  coverage from session measurements. Used by
  `watch`/`report`/`check --system`.

The live path bypasses `BackendDriver`: session lifecycle there is
governed by `SessionController` hops plus the sensor seam, not by
the registry driver. ADR-0007 blesses this shape: batch owns
routing (registration-order sequence, skip receipts) while live
owns sensors, tick cadence, drains, stop handling, and
measurement-assembled coverage. Both sides share vocabulary and
per-event decode — the frozen `Backend::decode`/`finalize`
through `BackendRegistry` + `register_kcrypto_profile`, and
`DriverReport` checked transitions — and the conformance suite
gates drift between them (invariants I1–I5: observations,
coverage, integrity, per-backend facts, decoder identity).
Convergence is closed as "blessed, will not converge": cite
ADR-0007 instead of re-raising the split.

## Live data flow (kcrypto)

```text
 9 fexit progs, ordinals 0–8 (KPROG_ALLOC … KPROG_FINUP, ADR-0013)
   │  KAGG percpu aggregates   KRING ident records   KCTX ctx rows (ctx-v1)
   ▼                           ▼                     ▼
 KAGG ──fold──▶ agg rows ──┐
 KTOT ──fold──▶ totals row ─┤── snapshot_rows ──▶ decode ──▶ NativeObservation
 KRING ─drain─▶ ident rows ─┘      (KCFG-resolved)   (op/algorithm/driver/…)
 KCTX ──fold──▶ ctx rows ──▶ unknown = KTOT − ΣKCTX (Quiescent-gated)
   │                                     │
   └─ KIDN drops ──▶ SharedLosses ───────┴──▶ coverage + integrity + render

 stop: detach-first → CLOSED → poll KCTLCOUNT slots×lanes to zero →
   5 ms grace → rescan → Quiescent / Pending (ADR-0009/0010/0011)
 miss terminal → kernel_misses: exact claims need a clean 0 read (ADR-0013)
```

Maps (`KcryptoMaps`: `config`, `agg`, `total`, `ident`, `ring`,
`who`, `stack`, `err`, `params`, `drops`, `ctx`, `ctx_drops`,
`ctl_closed`, `ctx_ovf`, `ctl_count`) are owned by the loaded
sensor; the session drain is one `DrainThread` for all ticks
(2B-C1). `KTOT`, `KCTLCOUNT`, `KCTX_DROPS` carry one slot per
program ordinal (9) and `KDROPS` one per ordinal × site (72 =
9 × 8); userspace folds all slots × lanes, so no two writers
share a (slot, lane) pair and plain load/store is exact without
atomics (ADR-0013). Ordinals live in `kryprobe-abi` with a
GPL-2.0-safe twin in `kcrypto.rs`, pinned by `kprog_lanes.rs`.
Who attribution joins ident rows against per-tick kallsyms
(parsed once per tick, 2B-C2) with a cross-tick join cache.
Render reads typed payload keys (`payload_keys`); policy
evaluates the same observations against YAML rules.

## Vocabulary split: `session` / `snapshot` (1B-L5)

The same words name unrelated concepts per crate — deliberate, but
documented here so edits land in the right crate:

- `core::session`: the capture state machine (`SessionController`,
  open/run/close transitions). A *session* here is a lifecycle.
- `report::session`: the JSONL envelope records (`session_start` /
  `session_end`). A *session* here is a pair of wire records.
- `report::snapshot`: the wire `aggregate_snapshot` record (rendered
  aggregates qualified by integrity receipts).
- `privilege::kcrypto_snapshot`: BPF map reads (`SnapshotRows` —
  the raw per-tick rows decoded from the kcrypto maps).

Rule of thumb: *lifecycle* → core, *wire records* → report, *map
reads* → privilege. Renaming was considered and rejected: each name
is correct inside its crate, and the split above is the map.

## Trust boundaries

- Kernel entries: privilege only (ADR-0002, seam-gated).
- Process identity: (pid, start-time) (ADR-0003).
- BPF object loaded: the trusted path only when elevated
  (`docs/deployment.md`); dev tiers exist for unprivileged runs.
- Evidence never retains keys, PINs, passwords, payload bytes, or
  arbitrary target memory (allowlist-pinned: `kcrypto_allowlist`
  test against `docs/kcrypto-capture-allowlist.md`).
- Terminal exactness needs a `Quiescent` fence receipt
  (ADR-0008 §(e), ADR-0009/0010/0011): `Pending` keeps the sample
  a non-atomic sample, never exact. The fence proof holds on
  Linux x86-64 (TSO) only; other architectures are unproven
  (ADR-0011).
