<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# KryProbe

KryProbe is a Linux runtime cryptographic observer. It watches how
the system uses the kernel crypto API — and records what it observes
as structured session evidence: implementation inventories, operation
observations, coverage gaps, and integrity counters.

Design rules: discovered is not selected, selected is not entered,
entered is not returned, returned is not completed, and completed is
not succeeded. Zero observations are always qualified by interval and
coverage. Keys, PINs, passwords, payload bytes, and arbitrary target
memory are never retained. BPF backends never perform privileged
operations directly; they produce plans consumed by authority code.

Status: the kcrypto backend is live. Beyond the thin-spine
skeleton (session/target/authority model, CLI, reporting, synthetic
backend, BPF spine, token lane, bench receipts), this tree ships
system-wide kernel-crypto observation (`watch`/`report --system`),
policy checks (`check --system`), and token-delegated privileged
bring-up (`token mint|status`). `docs/commands.md` is the command
reference; this file is the overview.

The first public release is being prepared as **v0.1.0**. Read the
[release scope and measured limits](docs/releases/v0.1.0.md) before
deploying or publishing performance numbers. Kernel-crypto functionality
has live evidence; full performance qualification remains incomplete.
The [quick start](docs/kcrypto-quickstart.md) covers installation and capture.

## Backends

| Backend     | Status                                |
|-------------|---------------------------------------|
| `synthetic` | active (test-only scripted backend)   |
| `kcrypto`   | live-gated: `available`, `degraded` (names the failing capability gates), or `unavailable` (names the detect error) |

`kryprobe backends` prints the live states. The `synthetic` backend
uses the reserved wire id `0xFF`, which can never collide with a real
backend and is rejected by non-test decoders.

## Commands

```
kryprobe --version
kryprobe doctor [--json]
kryprobe backends [--json]
kryprobe inspect --pid N [--json]
kryprobe selftest synthetic [--out FILE]
kryprobe selftest bpf [--calls N] [--out FILE]
kryprobe selftest token-smoke
kryprobe token mint [--bin PATH] [--receipt PATH] [--force]
kryprobe token status [--bin PATH]
kryprobe watch --system [--source S] [--duration N] [--token PATH] [--kcrypto-profile P]
kryprobe report --system [--duration N] [--format human|json|jsonl] [--out FILE] [--source S] [--token PATH] [--kcrypto-profile P]
kryprobe report FILE
kryprobe check --system --policy FILE [--duration N] [--source S] [--token PATH] [--kcrypto-profile P]
kryprobe <command> --help   # per-command help with examples (exit 0)
kryprobe plan|observe|run ...   # honest stub: exits 4, see below
```

`doctor` prints the capability probe matrix and degrades honestly
without privilege. `backends` lists the table above. `inspect` takes a
bounded snapshot of one process. `selftest synthetic` runs a scripted
session twice and must produce byte-identical JSONL. `selftest bpf`
loads the spine object, attaches to a fixture, and reconciles exact BPF
counters against received events. `selftest token-smoke` exercises the
token-delegated load path (root-only lane). `token mint` is the root
one-shot file-cap grant; `token status` reports cap + pin usability
without privilege. `report FILE` validates a session file against the
frozen schema and renders counts, coverage, and integrity. (The old
`import` command is retired; historical `import_shell` records still
validate structurally — see `docs/commands.md`.)

`plan`, `observe`, and `run` parse their arguments and exit 4 with a
typed `unsupported-in-thin-spine` marker; they never pretend success.

`watch --system`, `report --system`, and `check --system` are the
system-wide kcrypto commands: `--system` select-all is the only v0.1
scope. `watch` renders continuous tables; `report` runs one bounded
capture (human, `json`, or validated event-v0 `jsonl`); `check`
evaluates one capture against an explicit policy file.
`--token PATH` overrides token discovery on all three
(see `docs/commands.md` and `docs/deployment.md`).
`--kcrypto-profile` selects `api-returns` (default, kernel 6.12+)
or `request-lifecycle` (per-request lifecycles, needs kernel 7.0+);
the profile × family × boundary × provider × kernel table lives in
`docs/kcrypto-support.md`.

## Exit codes

The family below is pinned by test (`readme_pins_usage_exits`): it is
the `USAGE` text verbatim, so README edits cannot drift from the CLI.

| Code | Meaning              |
|------|----------------------|
| 0    | clean/ok             |
| 1    | internal failure     |
| 2    | usage/invalid input  |
| 3    | inconclusive/PARTIAL |
| 4    | environment-unusable |
| 10   | policy violation     |

## Building and testing

`cargo xtask` is the only supported orchestration entry point:

```
cargo xtask build --bpf # prerequisite for release-consumer tests on a fresh checkout
cargo xtask build       # workspace binaries, including host-test fixtures
cargo xtask check       # pinned-toolchain gate + fmt + clippy + doc + host tests
cargo xtask test host   # cargo test --locked --workspace
cargo xtask test bpf    # BPF pipeline lane (object + fixture + suites)
cargo xtask verify generated  # schema-freeze + fixture-validation tests
cargo xtask bench [--json]    # attach/drain/elf/e2e receipts (exit 4 when denied)
```

`xtask check` fails fast when the active `rustc` is not the pinned
toolchain and prints the install command.

## Toolchain prerequisites

- Rust 1.98.0 stable, managed by rustup. `rust-toolchain.toml` pins
  the exact version; running any `cargo` command installs it
  automatically when missing. Crates use edition 2024.
- Linux 6.12 or newer on x86-64. Capability probes are authoritative;
  kernel release alone never decides support.
- BPF lane (spine object build, `selftest bpf`, token smoke): the
  pinned nightly toolchain and `bpf-linker` (no clang needed: there
  are no C BPF sources). Exact pins live in
  `docs/dependencies/pins.md`. Privileged rows need
  `cap_bpf`/`cap_perfmon` or root; without them the probes report
  typed `Denied` rows instead of failing.
- The spine object loads without kernel BTF. Kernel-crypto observation
  needs target BTF (`/sys/kernel/btf/vmlinux`); without it the kcrypto
  rows report `unavailable` and the live commands exit 4.

## Development

`docs/commands.md` is the command reference; `AGENTS.md` holds the
agent workflow rules. Human contributors need three procedures:

- Gate: `cargo xtask check` (pinned toolchain, fmt, clippy, doc,
  host tests) is the required pre-merge gate; first run both build commands
  on a fresh checkout, using that worktree's own `target/` directory.
  Run the gate, not bare
  `cargo test` (which skips the seam gate, the pins, and `--locked`).
  CI enforces the same gate plus the BPF lane and supply scans.
  Behavior changes land with tests; output-shape changes update the
  goldens below.
- Privileged lanes: `cargo xtask test bpf` builds the BPF objects
  and runs the runnable privileged suites (honest `Denied` without
  caps). The sudo lanes (`#[ignore]`d tests naming \"the lane lock\"
  or a lease) run under sudo with the workspace lane lock —
  lane-exclusive, never alongside other BPF activity.
- Goldens: byte-exact expectations live under `tests/goldens/` (CLI,
  report) and `tests/fixtures/`. When a change intentionally alters
  output, run once with `KRYPROBE_UPDATE_GOLDENS=1` (rewrites the
  file, prints `GOLDEN-UPDATED`, still fails), inspect the diff, then
  re-run to confirm green. Never update a golden to silence a
  mismatch you do not understand.

## Session schema

`schemas/event-v0.schema.json` is the frozen `kryprobe.event/v0`
envelope. It never changes in place: any change requires an ADR plus a
version bump, additive only.

## License

Userspace code is GPL-3.0-or-later: see `LICENSE` and
`LICENSES/GPL-3.0-or-later.txt`. Every new file carries an SPDX header.
BPF program sources are GPL-2.0-only with a kernel-visible `GPL`
license string.
