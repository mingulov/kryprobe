<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# BPF dependency pins (T7b)

Exact triple verified by building `spine.bpf.o` on 2026-09-17;
the kcrypto row verified against `kcrypto.bpf.o` in-tree.

## Pins

- Nightly: `nightly-2026-09-16` →
  `rustc 1.100.0-nightly (215a8af4b 2026-09-15)`.
  Newer than 1.98.0 ✓. Pinned in
  `crates/bpf-spine/rust-toolchain.toml` and
  `crates/bpf-kcrypto/rust-toolchain.toml` (dated channel, not
  floating `nightly`: the floating channel already rolled to a
  different commit).
- bpf-linker: `0.10.4` (preinstalled;
  `~/.local/share/mise/shims/bpf-linker` on PATH).
- aya-ebpf: `=0.2.1` (exact pin in both
  `crates/bpf-spine/Cargo.toml` and
  `crates/bpf-kcrypto/Cargo.toml`; crates.io latest in the 0.2 line).
- clang: not required (no C BPF sources; bpf-linker is prebuilt).
  Inspection uses the system `llvm-readelf`/`llvm-strip`.

Both BPF crates carry their own committed `Cargo.lock` (they build
outside the host workspace): bump either only with the same dated
nightly, then re-verify the section list below. The `=0.2.1` pins
are the policy; the lockfiles are the receipt.

## Install / verify

```sh
rustup toolchain install nightly-2026-09-16 -c rust-src --profile minimal
rustc +nightly-2026-09-16 --version   # want 1.100.0-nightly (215a8af4b 2026-09-15)
bpf-linker --version                  # want 0.10.4
cargo xtask build --bpf               # builds + copies both objects
llvm-readelf -S target/kryprobe-bpf/spine.bpf.o   # expect uprobe.multi, uretprobe.multi, maps, license
llvm-readelf -S target/kryprobe-bpf/kcrypto.bpf.o # expect 9 fexit/*, maps, license
```

## Object rows

| Object | Crate | Strip recipe | Sections |
|--------|-------|--------------|----------|
| `spine.bpf.o` | `bpf-spine` | `GcDeadFuncs` (reachability GC over `.text`) | `uprobe.multi`, `uretprobe.multi`, 5 map defs, `license` = `GPL\0`, no `.BTF` |
| `kcrypto.bpf.o` | `bpf-kcrypto` | `DropUnreferencedText` (drop text no program references) | 9 `fexit/*` (`crypto_alloc_tfm_node`, `crypto_destroy_tfm`, `crypto_skcipher_encrypt/decrypt`, `crypto_aead_encrypt/decrypt`, `crypto_ahash_digest`, `crypto_shash_digest/finup`), maps, `license` |

Recipes live in `xtask/src/bpf/mod.rs` (`Strip`) and
`xtask/src/bpf/strip.rs`; the loader re-checks reachability at
parse time and fails closed naming the dead function.

## Accepted warnings (not blockers)

- bpf-linker prints `unable to open LLVM shared lib
  .../libLLVM-23-rust-1.100.0-nightly.so: dlopen failed` and falls back
  to its bundled LLVM. Output verified correct: eBPF relocatable,
  `uprobe.multi`/`uretprobe.multi` sections, 5 map defs, `license`
  = `GPL\0`, map relocations for the raw loader, no `.BTF` section
  (BTF-free load by construction).

## Fork rule

Not fired: raw loader path, no vendoring. No `third-party/` content.

## Build quirks (T12 root-cause notes)

- Dead builtins: rustc exports `memcpy`/`memmove`/`memset` as link
  roots and bpf-linker has no GC, so uncalled builtins land in
  `.text` and the kernel verifier rejects the program. `build --bpf`
  strips unreachable `.text` functions after the link
  (`xtask/src/bpf/strip.rs`, 1808 → 1200 bytes); the loader
  re-checks reachability at parse time and fails closed naming the
  dead function. `--disable-memory-builtins` does not help (it only
  stops bpf-linker from *injecting* missing builtins, not from
  keeping linker-pulled ones), and `LTO` is blocked by build-std's
  `-C embed-bitcode=no`.
- `spine.rs` writes the ring slot field-by-field through the entry
  deref: any 28-byte zero chain (repeat-expr, loop, literal list)
  fuses back into a `memset` call, which would reintroduce a real
  builtin reference. Volatile stores keep the tail call-free.
- bpf-linker `0.10.4` hung once (7+ min CPU spin on a <1s link, same
  input linked fine on retry): suspected flake in the bundled-LLVM
  fallback under load, not yet reproduced deterministically.
  `build --bpf` has no hang workaround; retry the build if it stalls.
- The host kernel answers `EOPNOTSUPP` to `BPF_TOKEN_CREATE` on every
  bpffs instance tried (private delegated mount and system bpffs,
  all fd modes, `unprivileged_bpf_disabled` 2 and 0): the token lane
  honestly reports `Denied{token-create}` (errno 95) here. Full
  `TOKEN-LOAD-PASS` needs a kernel that supports token creation.
