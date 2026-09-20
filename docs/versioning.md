# Versioning policy (1B-M5)

Five markers version four independent surfaces. Each marker versions
exactly one surface; a change to one surface never bumps another
marker's version.

| Marker | Surface | Scheme | Current |
|---|---|---|---|
| `ABI_VERSION` (`kryprobe-abi/src/ids.rs`) | BPF↔host wire header (`RawEventHeader`) | `u16`, exact match | `0` |
| `EVENT_SCHEMA_V0` (`kryprobe-report/src/lib.rs`) | JSONL event envelope `schema` field | frozen string | `kryprobe.event/v0` |
| `CONTRACT_VERSION_V0` (`kryprobe-report/src/lib.rs`) | `session_start` payload `contract_version` | frozen string | `v0-proposed` |
| `SHELL_SCHEMA_V1` (`kryprobe-report/src/adapters.rs`) | import-shell `schema` field | frozen string | `kryprobe/shell/v1` |
| policy `version` (`kryprobe-policy/src/rule.rs`) | policy YAML language | `u32`, exact match | `1` |

## Bump rules

- A marker bumps only when its surface's wire/parse contract changes in
  a way an old reader could misread (removed/renamed field, changed
  semantics, widened enum with new meaning). Additive, ignorable
  changes do not bump.
- Bumping means adding the new const/value next to the old one and
  updating this table — never editing a frozen value in place.
- `ABI_VERSION` is carried in every BPF event header; the BPF and host
  sides must agree or `split_header` refuses the event (fail-closed).

## Reader tolerance

All readers are strict today (accept-N only, reject anything else):

- `split_header` rejects any `RawEventHeader.version != ABI_VERSION`.
- The JSONL validator requires exactly `EVENT_SCHEMA_V0` on every
  record.
- `validate_shell` requires exactly `SHELL_SCHEMA_V1`.
- The policy parser accepts only `version: 1` (any other version is a
  usage error, exit 2).

Rationale: kryprobe versions its surfaces before it has more than one
of anything — strictness keeps every incompatibility loud and
attributed. If a second live version ever ships, the policy for that
surface moves to accept-N/N-1 with a migration note recorded here;
until then, strict rejection is the documented behavior, not an
oversight.
