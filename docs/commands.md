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
kryprobe doctor [--json] [--versions]
kryprobe backends [--json]
kryprobe inspect --pid N [--json]
kryprobe selftest synthetic [--out FILE]
kryprobe selftest bpf [--calls N] [--out FILE]
kryprobe selftest token-smoke
kryprobe watch --system [--source S] [--duration N] [--token PATH]
kryprobe report --system [--duration N] [--format human|json|jsonl] [--out FILE] [--source S] [--token PATH]
kryprobe report FILE
kryprobe check --system --policy FILE [--duration N] [--source S] [--token PATH]
kryprobe import FILE
kryprobe token mint [--bin PATH] [--receipt PATH] [--force]
kryprobe token status [--bin PATH]
kryprobe plan|observe|run ...   # stub: exit 4, typed marker
```

- `doctor` prints the capability probe matrix (`Pass`/`Denied`/
  `Skipped`, every denial naming stage + errno) plus backend rows.
  `doctor --versions [--json]` prints artifact versions instead:
  binary + kcrypto/spine object paths + sha256 + the
  `pins_enforced` bit (see `docs/json.md`).
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
  `report` renders `--format human` (default), `json`, or `jsonl`
  (validated event-v0 JSONL: session envelope records, same
  coverage verdict as the human trailer) to stdout or `--out`
  (exit 0 complete, 3 partial); `watch` renders the same
  tables and exits 0 on any completed capture. `check` requires
  `--policy` (no default policy; bad policy is exit 2, parsed before
  capture) and evaluates one capture against the explicit-rules
  policy: exit 10 prints `VIOLATION rule=…` plus stderr detail naming
  algorithm/driver/context/evidence, exit 0 prints `CLEAN`, exit 3
  prints `INCONCLUSIVE missing=…`. Unusable lanes exit 4 in all
  three. Workload selectors (`--pid`, `--tree`, `--cgroup`,
  `--cgroup-id`, `--unit`) and `--comm` filters are deferred past v0.1
  and rejected naming the deferral.

- Live sessions and SIGINT (4B-M5): Ctrl-C never kills a capture
  mid-flight. The session finalizes, renders the partial window it
  captured, and exits 3 (`check` still exits 10 when the verdict
  fired on the cut-short window). Every tick also prints one
  stderr progress line (`kryprobe: progress tick=N rows=M
  drops=K`) — human-only, unstable, never script on it.
- Session bounds (4B-M5): observations accumulate in memory for
  the whole window (agg rows dedup by key, but idents keep every
  tick), so memory grows with ticks × rows — roughly 1KB per kept
  observation. Prefer bounded `--duration` (minutes, not days; the
  60s default is sized for triage, and hour-long windows stay under
  ~100MB on quiet hosts but grow with crypto activity). Unbounded
  `watch` is for attended use with closed-stdin/SIGINT stops. A
  streaming sink that removes the bound is tracked as 2B-H2.
- `import FILE` reads one osslscope report (`schema_version:
  observed-crypto-v1[.minor]`) or p11scope profile (`schema:
  p11scope/observed-profile/v3`) doc and emits one shell JSONL record
  (`schema: kryprobe/shell/v1`) to stdout: mapped fields best-effort
  plus `native` carrying the FULL original doc verbatim. Unprivileged;
  exit 0 on success, 2 on unreadable/invalid input or an unknown schema
  marker (naming the marker found), 1 on internal failure. Shell
  shape (`schemas/shell-v1.schema.json`): `schema` (always
  `kryprobe/shell/v1`), `source` (`osslscope`|`p11scope`), then
  best-effort `scope`, `context`, `operation`, `implementation`,
  `metrics`, `window`, `evidence`, and `native` (the full original
  doc, always present).
- `token mint` is the root one-shot file-cap grant (the spec §3.3
  `setcap` fallback): it writes a `security.capability` xattr
  granting `cap_bpf,cap_perfmon+ep` on `--bin` (default: the running
  binary, resolved; symlink targets are refused) plus a JSON receipt
  to stdout or `--receipt`. Exit 0 on success; exit 4 without root;
  exit 2 on a bad `--bin` path, on a target that is not the running
  kryprobe binary without `--force`, or on receipt-overwrite without
  `--force`. See `docs/deployment.md` for the deploy runbook
  (install → `mint` → verify, re-mint after every binary swap).
- `token status` reports file caps + token-pin usability for `--bin`
  (default: the running binary). Never privileged; exit 0 always
  (findings ride the output, not the exit code).
- `watch`/`report --system`/`check --system` accept `--token PATH`
  to point BPF token-FD delegation at an explicit bpffs pin (see the
  env table: `--token` beats `KRYPROBE_TOKEN` beats default-pin
  discovery).

## Environment overrides

| Variable | Used by | Meaning |
|----------|---------|---------|
| `KRYPROBE_BPF_DIR` | kcrypto object locator | Dir (or file, tried as-is) joined with `kcrypto.bpf.o`; tier 1 of the D2 try order. Ignored when elevated. |
| `KRYPROBE_BPF_OBJ` | `selftest bpf`, benches | Spine object path (default: `target/kryprobe-bpf/spine.bpf.o`). Ignored when elevated. |
| `KRYPROBE_FIXTURE` | `selftest bpf`, benches | `spine_fixture` binary path (dev-only override). Ignored when elevated — an elevated selftest never executes an env-steered helper. |
| `KRYPROBE_TOKEN_WORKER` | lane tests | `token_worker` binary path (dev-only override, same elevated rule). |
| `KRYPROBE_TOKEN` | `watch`/`report`/`check`, `token status` | BPF token bpffs pin path (a path, not a credential): `--token` > env > default-pin discovery. |
| `KRYPROBE_SMOKE_WORKER` | `token_worker` | Internal spawn marker (`=1` only; set by the spawner, not operators). |
| `KRYPROBE_UPDATE_GOLDENS` | testkit golden tests | When `=1`, a golden mismatch rewrites the file instead of failing (tests only, never product). |
| `KRYPROBE_PIN_DIGESTS` | `kryprobe-privilege` build | Comma-separated sha256 pins for release BPF objects (build-time; see below). |
| `KRYPROBE_REQUIRE_PINS` | `kryprobe-privilege` build | When `=1`, an empty `KRYPROBE_PIN_DIGESTS` fails the build instead of baking a silently unpinned binary (release packaging sets this). |

Object-locator try order (D2): `KRYPROBE_BPF_DIR` (or file as-is) →
exe-relative `kryprobe-bpf/kcrypto.bpf.o` (the bundled/install tier)
→ CWD-relative `target/kryprobe-bpf/kcrypto.bpf.o` (dev tier).
Security note: env and CWD tiers exist for unprivileged dev/test
only. An elevated process (euid 0 or effective `CAP_BPF`/
`CAP_SYS_ADMIN`, i.e. any file-cap deployment) loads only the
exe-bundled tier — so a hand-rolled deploy fails closed (exit 4,
`kcrypto_object_unreadable`) instead of loading a stray object — and
pinned builds (non-empty `KRYPROBE_PIN_DIGESTS` baked at compile
time) additionally refuse any object whose sha256 is not in the pin
set. Unpinned builds skip the check with a once-per-process stderr
warning and report `pins_enforced: false` in `doctor --versions`;
release packaging must set `KRYPROBE_REQUIRE_PINS=1` so a missing
pin set fails the build instead of shipping unpinned. `doctor`
prints the resolved object path (`kcrypto_object` row) so the
effective configuration is inspectable. The normative trusted path
is `docs/deployment.md`.

## Privileged runs

One command (4B-H2): `scripts/sudo-lane.sh` runs the full
privileged lane under the BPF lane lock — builds, `cargo xtask
test bpf` (unprivileged honest-denial asserts), the sudo
selftests, and every `#[ignore]`d suite binary under sudo. It
needs root or passwordless sudo, else it exits 4 (`NOT_RUN`).

```sh
scripts/sudo-lane.sh
```

The equivalent manual steps (what the script runs):

```sh
sudo ./target/debug/kryprobe selftest bpf --calls 20000  # expect exit 0, reconcile: clean
sudo ./target/debug/kryprobe selftest token-smoke        # exit 0 (pass) or 4 (Denied, kernel-dependent)
```

plus each workspace test binary's `--ignored` set under sudo
(see the thin-spine evidence receipts). Until the self-hosted
privileged runner exists, schedule the script by hand and record
unavailable lanes `NOT_RUN` per `AGENTS.md`.
