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
