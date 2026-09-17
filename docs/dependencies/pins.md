<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# BPF dependency pins (T7b)

Exact triple verified by building `spine.bpf.o` on 2026-09-17.

## Pins

- Nightly: `nightly-2026-09-16` →
  `rustc 1.100.0-nightly (215a8af4b 2026-09-15)`.
  Newer than 1.98.0 ✓. Pinned in
  `crates/bpf-spine/rust-toolchain.toml` (dated channel, not floating
  `nightly`: the floating channel already rolled to a different commit).
- bpf-linker: `0.10.4` (preinstalled;
  `~/.local/share/mise/shims/bpf-linker` on PATH).
- aya-ebpf: `=0.2.1` (exact pin in
  `crates/bpf-spine/Cargo.toml`; crates.io latest in the 0.2 line).
- clang: not required (no C BPF sources; bpf-linker is prebuilt).
  Inspection uses the system `llvm-readelf`/`llvm-strip`.

## Install / verify

```sh
rustup toolchain install nightly-2026-09-16 -c rust-src --profile minimal
rustc +nightly-2026-09-16 --version   # want 1.100.0-nightly (215a8af4b 2026-09-15)
bpf-linker --version                  # want 0.10.4
cargo xtask build --bpf               # builds + copies the object
llvm-readelf -S target/kryprobe-bpf/spine.bpf.o   # expect uprobe.multi, uretprobe.multi, maps, license
```

## Accepted warnings (not blockers)

- bpf-linker prints `unable to open LLVM shared lib
  .../libLLVM-23-rust-1.100.0-nightly.so: dlopen failed` and falls back
  to its bundled LLVM. Output verified correct: eBPF relocatable,
  `uprobe.multi`/`uretprobe.multi` sections, 5 map defs, `license`
  = `GPL\0`, map relocations for the raw loader, no `.BTF` section
  (BTF-free load by construction).

## Fork rule

Not fired: raw loader path, no vendoring. No `third-party/` content.
