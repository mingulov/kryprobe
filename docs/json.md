<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Machine-readable output shapes (3B-L4)

Field tables for the JSON documents. Stability: the `report
--format json` top-level keys and the exit-code family are stable;
`doctor`/`backends`/`inspect` shapes are best-effort diagnostic
output and may gain keys (consumers must ignore unknown keys, never
require exact key sets). Event-v0 JSONL (`report --format jsonl`,
`report FILE`, selftests) is schema-pinned instead — see
`schemas/event-v0.schema.json` — and the import shell has
`schemas/shell-v1.schema.json`.

Stderr is human-only and unstable (4B-M4): progress lines
(`kryprobe: progress …`), warnings, and diagnostics may change or
vanish without notice — never script on them. The one exception is
the JSON-mode audit trail below: lines whose object carries an
`"audit"` key follow the documented audit shapes (same
best-effort stability as `doctor`: may gain keys, never silently
change meaning).

## `doctor --json`

```text
{
  "probes": [{"name": str, "outcome": "pass"|"denied"|"skipped"|"failed",
              "detail": str?, "stage": str?, "errno": i32?, "reason": str?}],
  "backends": [{"id": str, "state": str, "note": str|null}],
  "coverage_profile": str,
  "verdict": {"status": "ready"|"degraded", "missing": [str]}
}
```

Outcome payloads: `pass` carries `detail`; `denied` carries
`stage` + `errno`; `skipped` carries `reason`; `failed` carries
`detail` (never an errno — there was none).

## `doctor --versions [--json]`

```text
{"binary": str, "kcrypto": {"path": str, "sha256": str}|null,
 "spine": {"path": str, "sha256": str}|null, "pins_enforced": bool}
```

`binary` is the crate version; `kcrypto` is the pin-trusted object
the locator resolved (null when none is present); `spine` is the
best-effort exe-bundled/dev-layout object (null when not built —
thin spine loads no spine object); `pins_enforced` is false exactly
when the build baked an empty pin set (dev build: the pin check is
skipped with a stderr warning). Best-effort diagnostic stability.

## `backends --json`

```text
{"backends": [{"id": str, "state": str, "note": str|null,
               "capabilities": {"uprobe_multi": bool, "cookies": bool,
                                "ringbuf": bool, "btf": bool}|null}]}
```

`capabilities` is present for `synthetic` (static gates) and
`kcrypto` (live gates), null for uninstalled backends.

## `inspect --pid N --json`

```text
{"pid": u32, "starttime": u64, "exe_dev": u64, "exe_ino": u64,
 "exe_size": u64, "maps_lines": u64, "maps_first_dev": str,
 "yama_scope": u32, "caps": str}
```

## `report --system --format json`

Top-level keys (pinned order): `observations`, `coverage`,
`integrity`, `verdict`. `verdict` is
`{"status": "complete"|"partial", "missing": [str]}` with `missing`
naming the uncovered kp2 dimensions in core order. `observations`
is the `NativeObservation` serde shape; `coverage` the
`CoverageSummary` serde shape.

## JSON-mode audit trail (stderr, 4B-M4)

`report --system --format json|jsonl` emits one structured stderr
line per privileged operation (human formats stay silent):

```text
{"audit": "object-load", "path": str, "sha256": str}
{"audit": "attach", "attached": u64, "expected": u64}
```

`object-load` names the staged BPF object and its digest;
`attach` reports attached vs expected probe points. Filter stderr
for lines parsing as JSON objects with an `"audit"` key; every
other stderr line is human-only/unstable.

## `token mint` receipt JSON

```text
{"mechanism": "setcap", "binary": str, "caps": ["cap_bpf", "cap_perfmon"],
 "effective": true, "kernel": str, "time": str}
```

`time` is UTC (`YYYY-MM-DDTHH:MM:SSZ`); `kernel` is the release
string. The receipt records what was granted where — it is
evidence, not a credential.
