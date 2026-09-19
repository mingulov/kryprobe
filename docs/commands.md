<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Command reference

`cargo xtask` is the only supported orchestration entry point; `kryprobe`
is the product CLI. Exit codes (kp2 family): 0 clean/ok, 1 internal
defect, 2 usage/invalid input, 3 inconclusive/PARTIAL (ran, gaps
noted, never silent), 4 environment-unusable (denied, missing
artifacts, uninstalled backends), 10 confirmed policy violation
(`check` only).

## `cargo xtask` lanes

| Lane | Command | Notes |
|------|---------|-------|
| Gate | `cargo xtask check` | Pinned toolchain + fmt + clippy + host tests; exit 0 is `BUILD_DONE`/`CHECK_EXIT=0`. |
| Build | `cargo xtask build` | `cargo build --locked --workspace` (host only). |
| BPF build | `cargo xtask build --bpf` | Nightly build of `spine.bpf.o`, dead-strip, copy to `target/kryprobe-bpf/`. |
| BPF lane | `cargo xtask test bpf` | Builds bins + object, runs privileged suites incl. `--include-ignored`; honest `Denied` without caps. |
| Host tests | `cargo xtask test host` | `cargo test --locked --workspace`. |
| Verify | `cargo xtask verify generated` | Regeneration goldens byte-identical. |
| Bench | `cargo xtask bench` | attach/drain/elf/e2e receipts (or typed denials); needs privilege for attach/drain rows. |

## `kryprobe` commands

```
kryprobe --version
kryprobe doctor [--json]
kryprobe backends [--json]
kryprobe inspect --pid N [--json]
kryprobe selftest synthetic [--out FILE]
kryprobe selftest bpf [--calls N] [--out FILE]
kryprobe selftest token-smoke
kryprobe watch --system [--source S] [--duration N]
kryprobe report --system [--duration N] [--format human|json] [--out FILE] [--source S]
kryprobe report FILE
kryprobe check --system --policy FILE [--duration N] [--source S]
kryprobe import FILE
kryprobe plan|observe|run ...   # stub: exit 4, typed marker
```

- `doctor` prints the capability probe matrix (`Pass`/`Denied`/
  `Skipped`, every denial naming stage + errno) plus backend rows.
- `backends` lists the registry (`synthetic` active test-only;
  `p11`/`openssl` not installed; `kcrypto` unavailable).
- `inspect` snapshots one process (bounded maps/exe/ELF reads;
  gone/bad pids are typed errors, never panics).
- `selftest synthetic` runs the scripted session (twice internally)
  and emits byte-identical JSONL (`DETERMINISTIC`); validates and
  renders a summary to stderr.
- `selftest bpf` runs load → attach → drain → reconcile against the
  fixture (default 200 calls): exit 0 prints `reconcile: clean` plus
  `entries=/returns=/received=/ring=/drop=/queue=` counts; exit 3
  prints `reconcile: partial`; exit 4 prints `Denied{stage}`.
  The JSONL carries session start/end only (with the fixture exit
  code); per-event observations would claim backend coverage the
  lane has no backend for.
- `selftest token-smoke` mints a token over a private bpffs mount
  and runs the nobody worker (root-only; exit 4 otherwise, or when
  the kernel answers `EOPNOTSUPP`/`EPERM`). SERIAL LANE: run with no
  concurrent BPF activity on the host — ambient teardown mid-lane is
  tolerated (extras-only leak comparison), but any map/program loaded
  by another process during the roundtrip reports `Leaked` honestly.
- `report FILE` validates a JSONL stream against the frozen schema
  (exit 2 on corrupt input) and renders phase tables, coverage, and
  integrity.
- `watch --system`, `report --system`, and `check --system` are the
  system-wide kcrypto commands (kp2 §2–§3): `--system` select-all is
  the only v0.1 scope, so fork/exec, new containers, and module loads
  need no new probes. `--duration` is a window in seconds (`>= 1`,
  60s default for `report`/`check`); `--source` accepts only
  `kernel-crypto` (other sources arrive with their backends); live
  `report` renders `--format human` (default) or `json` to stdout or
  `--out` (exit 0 complete, 3 partial); `watch` renders the same
  tables and exits 0 on any completed capture. `check` requires
  `--policy` (no default policy; bad policy is exit 2, parsed before
  capture) and evaluates one capture against the explicit-rules
  policy: exit 10 prints `VIOLATION rule=…` plus stderr detail naming
  algorithm/driver/context/evidence, exit 0 prints `CLEAN`, exit 3
  prints `INCONCLUSIVE missing=…`. Unusable lanes exit 4 in all
  three. Workload selectors (`--pid`, `--tree`, `--cgroup`,
  `--cgroup-id`, `--unit`) and `--comm` filters are deferred past v0.1
  and rejected naming the deferral.
- `import FILE` reads one osslscope report (`schema_version:
  observed-crypto-v1[.minor]`) or p11scope profile (`schema:
  p11scope/observed-profile/v3`) doc and emits one shell JSONL record
  (`schema: kryprobe/shell/v1`) to stdout: mapped fields best-effort
  plus `native` carrying the FULL original doc verbatim. Unprivileged;
  exit 0 on success, 2 on unreadable/invalid input or an unknown schema
  marker (naming the marker found), 1 on internal failure.

## Environment overrides

| Variable | Used by | Meaning |
|----------|---------|---------|
| `KRYPROBE_BPF_OBJ` | `selftest bpf`, benches | Spine object path (default: `target/kryprobe-bpf/spine.bpf.o`). |
| `KRYPROBE_FIXTURE` | `selftest bpf`, benches | `spine_fixture` binary path. |
| `KRYPROBE_TOKEN_WORKER` | lane tests | `token_worker` binary path. |

## Privileged runs

```sh
sudo ./target/debug/kryprobe selftest bpf --calls 20000  # expect exit 0, reconcile: clean
sudo ./target/debug/kryprobe selftest token-smoke        # exit 0 (pass) or 4 (Denied, kernel-dependent)
```

`cargo xtask test bpf` runs unprivileged with honest-denial asserts;
for the strict privileged asserts, run the built suite binaries
under `sudo` (see the thin-spine evidence receipts).
