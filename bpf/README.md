<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# BPF layout

BPF program sources live in crates, not in this directory: `bpf/`
holds only this pointer file. The actual layout:

- `crates/bpf-spine/` → `spine.bpf.o`: the common object (shared
  maps plus entry/return selftest probes), built in T7.
- `crates/bpf-kcrypto/` → `kcrypto.bpf.o`: the kcrypto sensor (9
  fexit programs over the kernel crypto API, aggregates, ident
  ring), BTF-dependent.

`cargo xtask build --bpf` builds both objects into
`target/kryprobe-bpf/` (pins, strip recipes, and expected sections
in `docs/dependencies/pins.md`); the raw userspace loader loads
them — no `bpf/` sources are compiled, now or ever. Backend crates
live under `crates/`; there is intentionally no top-level
`backends/` directory.

Historical note: this file once reserved a `bpf/userspace` +
`bpf/kcrypto` split per pack proposal P-001 (see
`docs/sources.md`); the tree instead grew one crate per object,
which is the layout above.
