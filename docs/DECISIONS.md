<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Decisions (3B-H1/M5)

Index of Architecture Decision Records. `AGENTS.md` requires reading
this file before editing; the procedure is: read the index, then any
ADR your change touches, then the owning code.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-0002](decisions/ADR-0002.md) | Privilege seam (Rules A/B) | Accepted (reconstructed) |
| [ADR-0003](decisions/ADR-0003.md) | Process identity is (pid, start-time) | Accepted (reconstructed) |
| [ADR-0004](decisions/ADR-0004.md) | Kernel-crypto-only product scope | Accepted (owner-directed 2026-09-24) |
| [ADR-0005](decisions/ADR-0005.md) | kcrypto lifecycle semantics + payload-v1 | Accepted (T05, 2026-09-24) |
| [ADR-0006](decisions/ADR-0006.md) | fsession lifecycle sensor, kernel floor 7.0+ | Accepted (T06 round-8 rework, 2026-09-25) |
| [ADR-0007](decisions/ADR-0007.md) | dual session drivers — batch vs live-loop split blessed | Accepted (krypto-driver-seam Task 1, 2026-10-01) |
| [ADR-0008](decisions/ADR-0008.md) | M1 workload-context accounting contract (ctx-v1) | Accepted (M1 Task 01, 2026-10-02) |
| [ADR-0009](decisions/ADR-0009.md) | M1 fence mechanism — per-CPU count, no BPF atomics | Accepted (M1 Task 02, 2026-10-03) |
| [ADR-0010](decisions/ADR-0010.md) | M1 fence close order + visibility grace | Accepted (M1 Task 02, 2026-10-03; amends ADR-0009) |
| [ADR-0011](decisions/ADR-0011.md) | fence proof scope — x86-64 TSO + zombie argument | Accepted (M1 Task 02, 2026-10-03; amends ADR-0010) |
| [ADR-0012](decisions/ADR-0012.md) | M1 shared userland contract corrections (Stage 2A) | Accepted (M1 Stage 2A, 2026-10-09) |
| [ADR-0013](decisions/ADR-0013.md) | Per-program BPF lanes + universal kernel-miss surfacing | Accepted (M1 Task 06, 2026-10-12) |

ADR-0001 predates the tree's records and is not reconstructed (see
`docs/sources.md`).

## Creating a new ADR

1. Copy the shape of ADR-0002 (Status / Context / Decision /
   Consequences / Enforcement-or-Provenance).
2. Number it `ADR-NNNN`, next free number.
3. Add the row to this index.
4. Never edit an accepted ADR in place to change its meaning —
   supersede it with a new ADR.

## Rules

- Accepted ADRs describe the tree as it is: if code and an ADR
  disagree, the code wins and the ADR must be amended or superseded.
- Reconstructed ADRs (marked as such) document behavior recovered
  from enforcement and mechanism, not from a lost original text.
