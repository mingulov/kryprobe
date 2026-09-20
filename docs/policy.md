<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Policy guide

`kryprobe check --system --policy FILE` evaluates one capture
against an explicit-rules YAML policy (`version: 1` + `rules`;
unknown keys rejected). The full shape reference (MatchSpec key
table, glob dialect, worked example) lands with the completed guide;
this section normatively pins the verdict semantics.

## Verdicts

`check` reports one of three verdicts:

| Verdict | Exit | Meaning |
|---------|------|---------|
| `VIOLATION rule=…` | 10 | A `deny` rule matched. The finding stands even when other coverage is partial — a real observation is evidence. Stderr names algorithm/driver/context/evidence. |
| `CLEAN` | 0 | No `deny` matched **and** rule-dimension coverage is COMPLETE: absence is proven, not assumed. |
| `INCONCLUSIVE missing=…` | 3 | No `deny` matched but the capture cannot prove absence: coverage has gaps on rule dimensions (`missing` names them in core order). |

## Fail-closed rule (unevaluable rules)

A `deny` rule is evaluated only against observations carrying every
key it constrains. A `deny` rule with in-source observations but
none fully specified makes the capture `Inconclusive` (dimension
`evidence-shape`) — never `Clean`. Failing closed here is load-bearing:
a `Clean` verdict must mean "checked and absent", not "could not
evaluate". A rule with no in-source observations at all is
inapplicable, not unevaluable, and does not affect the verdict.
