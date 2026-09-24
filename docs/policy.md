<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Policy guide

`kryprobe check --system --policy FILE` evaluates one capture
against an explicit-rules YAML policy (`version: 1` + `rules`;
unknown keys rejected — exit 2 at the CLI, never silently
ignored). There is no default policy: `check` requires `--policy`.

## Example

```yaml
version: 1
rules:
  - id: no-kernel-md5
    source: kernel-crypto
    match:
      stage: executed
      algorithm: md5
    decision: deny
  - id: watch-external-drivers
    source: kernel-crypto
    match:
      driver_not: "*-generic"
    decision: deny
```

Rules evaluate in order; the first matching `deny` wins and the
verdict names its `id`. `source` scopes the rule to a capture
source (`kernel-crypto` in v0.1 — any other spelling parses but
never matches kcrypto data). `decision: report` never raises a
violation (v0.1 records nothing; the verdict only distinguishes
deny-vs-report).

## Match keys

`match` is a conjunction: every present key must hold, absent keys
are wildcards, `{}` matches everything in the rule's source.

| Key | Matches |
|-----|---------|
| `stage` | `selected` (transform/selection observed), `returned` (API invocation returned, no provider-entry claim), or `executed` (completion evidence observed — api-returns rows never match) |
| `algorithm` | Kernel algorithm name, exact or glob (`md5`, `cbc(*)`) |
| `driver` | Kernel driver name, exact or glob |
| `driver_not` | Matches when the `driver` glob does NOT match |
| `module` | Kernel module — **never matches kcrypto v0.1 data** (D4); import-shaped observations match their payload module |
| `family` | Crypto family (`skcipher`, `aead`, `ahash`, `shash`, …) |
| `operation` | Operation (`alloc`, `encrypt`, `decrypt`, `digest`, `finup`, …) — reads the payload `op` spelling |
| `result` | Immediate result class (`ok`, `error`, `queued`, …) |
| `context` | Context kind (`process`, `kthread`, `softirq`, …) |
| `comm` | Process comm glob (matches who-row `comm`) |
| `uid` | Exact uid (a YAML u32 — anything else is a policy parse error, exit 2) |

## Glob dialect

String keys are D5 globs: `*` spans any run (including empty),
`?` spans exactly one byte; everything else is literal —
brackets, backslashes, and braces never carry meaning. Matching
is byte-wise over the whole value. A missing payload key reads
as `""`, so a glob never matches absent data by accident.

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
