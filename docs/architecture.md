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

## The two session paths (tech debt: 1B-H1)

Two drivers run the `Backend` lifecycle, and they are not the same
code:

- `BackendDriver` (`core/src/backend/driver.rs`): the registry
  driver — detect → plan → configure → decode → finalize over
  owned backends, with skip receipts and exactly-once shared-loss
  feeds. Used by `backends` liveness, the driver lane test, and
  unit/integration tests.
- `drive_session` (`cli/src/live.rs`): the live driver — tick loop
  (snapshot → decode → who attribution) over a `SessionSensor`
  seam, finalize once, coverage from session measurements. Used by
  `watch`/`report`/`check --system`.

The live path bypasses `BackendDriver`: session lifecycle there is
governed by `SessionController` hops plus the sensor seam, not by
the registry driver. Converging the two (live sessions through the
driver, or the driver through the sensor seam) is open tech debt —
1B-H1 records it, and G3 deliberately scoped only the minimal seam.

## Live data flow (kcrypto)

```text
 9 fexit progs (crypto_alloc/skcipher/aead/ahash/shash …)
   │  KAGG percpu aggregates   KRING ident records
   ▼                           ▼
 KAGG ──fold──▶ agg rows ──┐
 KTOT ──fold──▶ totals row ─┤── snapshot_rows ──▶ decode ──▶ NativeObservation
 KRING ─drain─▶ ident rows ─┘      (KCFG-resolved)   (op/algorithm/driver/…)
   │                                     │
   └─ KIDN drops ──▶ SharedLosses ───────┴──▶ coverage + integrity + render
```

Maps (`KcryptoMaps`: `config`, `agg`, `total`, `ident`, `ring`) are
owned by the loaded sensor; the session drain is one `DrainThread`
for all ticks (2B-C1). Who attribution joins ident rows against
per-tick kallsyms (parsed once per tick, 2B-C2) with a cross-tick
join cache. Render reads typed payload keys (`payload_keys`);
policy evaluates the same observations against YAML rules.

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
