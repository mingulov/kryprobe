<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# KryProbe

KryProbe is a Linux runtime cryptographic observer. It watches how
processes use cryptographic interfaces — PKCS#11 providers, OpenSSL
providers, and the kernel crypto API — and records what it observes as
structured session evidence: implementation inventories, operation
observations, coverage gaps, and integrity counters.

Design rules: discovered is not selected, selected is not entered,
entered is not returned, returned is not completed, and completed is
not succeeded. Zero observations are always qualified by interval and
coverage. Keys, PINs, passwords, payload bytes, and arbitrary target
memory are never retained. BPF backends never perform privileged
operations directly; they produce plans consumed by authority code.

Status: thin-spine milestone complete. This tree holds the frozen
contracts and the executable skeleton (session/target/authority
model, CLI, reporting, synthetic backend, BPF spine, token lane,
bench receipts). No backend code from other trees is imported here;
backend ports plug into the `Backend` trait without redesign.

## Backends

| Backend     | Status               | Notes                                              |
|-------------|----------------------|----------------------------------------------------|
| `synthetic` | active (test-only)   | Deterministic scripted backend for self-tests      |
| `p11`       | not installed        | PKCS#11 backend; arrives with a later backend port |
| `openssl`   | not installed        | OpenSSL backend; arrives with a later backend port |
| `kcrypto`   | unavailable          | No backend; needs target BTF when implemented      |

The `synthetic` backend uses the reserved wire id `0xFF`, which can
never collide with a real backend and is rejected by non-test decoders.

## Commands

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
kryprobe plan|observe|run ...   # honest stub: exits 3, see below
```

`doctor` prints the capability probe matrix and degrades honestly
without privilege. `backends` lists the table above. `inspect` takes a
bounded snapshot of one process. `selftest synthetic` runs a scripted
session twice and must produce byte-identical JSONL. `selftest bpf`
loads the spine object, attaches to a fixture, and reconciles exact BPF
counters against received events. `selftest token-smoke` exercises the
token-delegated load path (root-only lane). `report` validates a
session file against the frozen schema and renders counts, coverage,
and integrity.

`plan`, `observe`, and `run` parse their arguments and exit 3 with a
typed `unsupported-in-thin-spine` marker; they never pretend success.

`watch --system`, `report --system`, and `check --system` are the
system-wide kcrypto commands: `--system` select-all is the only v0.1
scope. They parse fully and exit 3 until the kcrypto backend lands
(see `docs/commands.md`).

## Exit codes

| Code | Meaning                        |
|------|--------------------------------|
| 0    | ok                             |
| 1    | internal defect                |
| 2    | usage error                    |
| 3    | refused, unsupported, or denied|
| 4    | partial (some results, gaps noted) |

## Building and testing

`cargo xtask` is the only supported orchestration entry point:

```
cargo xtask check       # pinned-toolchain gate + fmt + clippy + host tests
cargo xtask build       # cargo build --locked --workspace
cargo xtask test host   # cargo test --locked --workspace
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
  will need target BTF when that backend is implemented.

## Session schema

`schemas/event-v0.schema.json` is the frozen `kryprobe.event/v0`
envelope. It never changes in place: any change requires an ADR plus a
version bump, additive only.

## License

Userspace code is GPL-3.0-or-later: see `LICENSE` and
`LICENSES/GPL-3.0-or-later.txt`. Every new file carries an SPDX header.
BPF program sources are GPL-2.0-only with a kernel-visible `GPL`
license string.
