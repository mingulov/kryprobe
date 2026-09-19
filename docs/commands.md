<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Command reference

`cargo xtask` is the only supported orchestration entry point; `kryprobe`
is the product CLI. Exit codes: 0 ok, 1 internal defect, 2
usage/invalid input, 3 refused/unsupported/denied, 4 partial (gaps
noted, never silent).

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
kryprobe plan|observe|run ...   # stub: exit 3, typed marker
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
  `entries=/returns=/received=/ring=/drop=/queue=` counts; exit 4
  prints `reconcile: partial`; exit 3 prints `Denied{stage}`.
  The JSONL carries session start/end only (with the fixture exit
  code); per-event observations would claim backend coverage the
  lane has no backend for.
- `selftest token-smoke` mints a token over a private bpffs mount
  and runs the nobody worker (root-only; exit 3 otherwise, or when
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
  need no new probes. `--duration` is a window in seconds (`>= 1`);
  `--source` accepts only `kernel-crypto` (other sources arrive with
  their backends); live `report` renders `--format human` (default) or
  `json` to stdout or `--out`; `check` requires `--policy` (no default
  policy). Workload selectors (`--pid`, `--tree`, `--cgroup`,
  `--cgroup-id`, `--unit`) and `--comm` filters are deferred past v0.1
  and rejected naming the deferral. All three parse fully and exit 3
  until the kcrypto backend lands; `check` reserves exit 10 for a
  confirmed policy violation (policy engine follow-up), never exited
  by the stub.

## Environment overrides

| Variable | Used by | Meaning |
|----------|---------|---------|
| `KRYPROBE_BPF_OBJ` | `selftest bpf`, benches | Spine object path (default: `target/kryprobe-bpf/spine.bpf.o`). |
| `KRYPROBE_FIXTURE` | `selftest bpf`, benches | `spine_fixture` binary path. |
| `KRYPROBE_TOKEN_WORKER` | lane tests | `token_worker` binary path. |

## Privileged runs

```sh
sudo ./target/debug/kryprobe selftest bpf --calls 20000  # expect exit 0, reconcile: clean
sudo ./target/debug/kryprobe selftest token-smoke        # exit 0 (pass) or 3 (Denied, kernel-dependent)
```

`cargo xtask test bpf` runs unprivileged with honest-denial asserts;
for the strict privileged asserts, run the built suite binaries
under `sudo` (see the thin-spine evidence receipts).
