<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Privileged-lane environment (4B-M6)

Minimal reproducible spec for the lanes that need BPF capability:
`cargo xtask test bpf`, the sudo `#[ignore]`d suites, and `selftest
bpf` / `selftest token-smoke`. Until a container/VM image is built
from this spec, reproduce lanes on any host meeting it — and record
deviations in the lane evidence.

## Host

- Linux x86-64, kernel 6.12+ with BTF (`/sys/kernel/btf/vmlinux`);
  7.0+ for the lifecycle sensor lanes (fsession attach).
- Privilege: root, or `cap_bpf,cap_perfmon+ep` on the kryprobe
  binary (`token mint` + `token status` to verify) plus a bpffs
  token pin when delegating.
- Exclusive: no concurrent BPF activity (the BPF lane lock
  serializes; ambient map/program churn fails leak comparisons
  honestly rather than silently).
- bpffs mounted where the token flow expects it
  (`docs/deployment.md`).

## Toolchain

- Host `rustc 1.98.0` (pinned `rust-toolchain.toml`; `xtask check`
  fails loud on skew).
- BPF `nightly-2026-09-16` + `rust-src` + `rustfmt` + `clippy`
  (both BPF crates pin it; `build --bpf` fails loud on skew and
  runs fmt + clippy gates per BPF crate before building).
- `bpf-linker 0.10.4` exactly (`build --bpf` gates the version).
- Inspection: `llvm-readelf`/`llvm-strip` (verified set: Ubuntu
  LLVM 21.1.8; record local versions in evidence).

## Kernel surface the lanes need

- `bpf()` syscall family (map create, prog load, link create,
  token create), `BPF_TRACE_FEXIT` attach, and
  `BPF_TRACE_FSESSION` attach for the lifecycle sensor lanes.
- AF_ALG (`algif_skcipher`/`algif_aead`/`algif_hash`) for the
  traffic fixtures; `cbc(aes)`, `ecb(aes)`, `gcm(aes)`,
  `sha256`, `md5` transforms loadable.

## Test-body prerequisites (env-gated, F-C3)

Two `live_k5` bodies need host prerequisites beyond root + BTF. When a
prerequisite is missing the body skips LOUDLY — it prints
`SKIP (env-gated): <body> requires <prereq>; see
docs/lane-environment.md` and exits 0 with its 1-passed summary. The
sudo runner accepts ONLY these two bodies' markers
(`scripts/sudo_lane.py::ENV_GATED_BODIES`); any other skip text, on
any body, still FAILs. The lane never installs prerequisites (no
shared-machine mutation); operators satisfy them out of band.

- `attribution_golden_python` requires `bpftrace` (the live oracle
  that counts digest returns alongside kryprobe for the EXACT
  equality golden). Debian/Ubuntu: `apt install bpftrace`;
  Fedora: `dnf install bpftrace`.
- `setcap_roundtrip_unpriv` requires the `nogroup` group: the
  unprivileged leg drops via
  `setpriv --reuid nobody --regid nogroup --clear-groups`.
  Debian-family systems provide `nogroup` (gid 65533); Fedora has
  no `nogroup` (there `nobody`'s group is `nobody`), so the body
  env-skips there. Do NOT rename the group per-distro in the
  test — the nobody-leg attestation pins `Uid: 65534` and the
  group is part of that pinned identity.

## What is NOT pinned (ambient, record in evidence)

- Exact kernel release past the applicable floor (6.12 base,
  7.0 lifecycle sensor — behavior gates on runtime probes, not
  the release string).
- CPU count (percpu fold lanes) and distro LLVM past the set above.
- Host crypto load (leak comparisons tolerate ambient-only extras).

## Running the lane (4B-H2)

`scripts/sudo-lane.sh` is the one-command lane: builds, the
unprivileged `cargo xtask test bpf` asserts, the sudo selftests,
and every `#[ignore]`d suite binary under sudo, serialized on
the host-global BPF lane lock (`/tmp/kryprobe-bpf-lane.lock`,
overridable via `KRYPROBE_LANE_LOCK`). It exits 4 with
`NOT_RUN` when root/passwordless sudo is unavailable. Until the
self-hosted privileged runner exists, schedule the script by
hand (nightly at minimum) and file the receipts as lane
evidence; threshold alerts follow `docs/bench-thresholds.md`.
