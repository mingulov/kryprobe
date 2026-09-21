<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Cited sources (3B-H1)

The tree cites documentation families that do not ship in the repo.
This file records what each family governs (from in-tree usage),
where its canonical home is when known, and what stands in for it
here. Nothing below invents the absent texts: a citation whose
source is unvendored is a pointer, not a proof — verify behavior
against code and tests, not against the citation.

## Vendo­red here (decisions with in-tree records)

| Family | Status | Record |
|--------|--------|--------|
| ADR-0002 (privilege seam) | Reconstructed from enforcement | `docs/decisions/ADR-0002.md` |
| ADR-0003 (process identity) | Reconstructed from mechanism | `docs/decisions/ADR-0003.md` |

Both are marked reconstructed: they document what the tree does
today. ADR-0001 predates the tree's records and is not
reconstructed — that number is a known gap, not an oversight.

## Unvendored (pointer only)

| Family | Governs (per in-tree usage) | Canonical home |
|--------|-----------------------------|----------------|
| CONTRACTS §1–§14 | Crate contracts: identities, wire enums, backend errors, plans, session machine, authority facets, evidence model | External pack; not vendored |
| ARCH §3, §4.6 | Backend crate layout; loader/relocation architecture | External pack; not vendored |
| kp2 §2–§13 | Product contract: live scope (§2–§3), trailer (§8), policy (§10), and others | External spec; not vendored |
| P-001 | Pack proposal for the BPF program layout (superseded in-tree by one-crate-per-object; see `bpf/README.md`) | External pack; not vendored |
| R-024 | Report rule: zero counts always carry their qualifier | Enforced in-tree by golden tests; no external text needed |
| D3–D12 | K2 design decisions (stage, module gating, globs, payload spellings, …) | Design notes; not vendored — behavior pinned by `policy_matrix` + payload-contract tests |
| T6–T12 | Task lanes (build, strip, smoke) | Lane notes; not vendored — procedures in `docs/dependencies/pins.md` |
| FU4 | Follow-fork/fan-out requirement | Specified in-tree by `docs/attach-policy.md` + ADR-0003 |

## Rule for new citations

Cite a vendored record (`docs/`, `decisions/`, schema files) or say
plainly that the source is external. Do not add new `CONTRACTS` /
`ARCH` / `kp2` section citations without vendoring the section or
recording it in the table above.
