<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# elf-access spike (T6b): mmap vs read, goblin vs minimal

## Decision

**Winner: `MmapGuard` reader + `minimal` parser** — fastest median warm
time on every fixture. Wired as the default in
`crates/kryprobe-privilege/src/elfread.rs`
(`pub use minimal::symbol_file_offset`, `MmapGuard` the documented reader).

## Matrix

Median of 9 timed iterations after 1 untimed warmup, per cell.
Workload per iteration: open the fixture + build the full dynamic-symbol
map (`Vec<(String, u64)>`, sorted). Times in milliseconds.

| fixture | bytes | symbols | mmap+goblin | mmap+minimal | full_read+goblin | full_read+minimal |
|---|---|---|---|---|---|---|
| small (spike binary itself) | 715,224 | 0 | 0.120 | **0.025** | 0.168 | 0.027 |
| libc (`libc.so.6`) | 2,190,608 | 3,054 | 0.516 | **0.414** | 0.814 | 0.545 |
| large (largest `.so` under `/usr/lib`: `libLLVM.so.21.1`) | 138,567,144 | 55,653 | 28.557 | **20.132** | 127.891 | 120.262 |

No tie anywhere, so the unsafe-line tiebreak did not fire
(for the record: `mmap.rs` has 3 `unsafe` sites, `minimal.rs` 0).

## Correctness oracle

`minimal` and `goblin_parser` returned byte-identical full symbol maps on
all three fixtures (`ORACLE-PASS`); neither parser was disqualified. The
standing oracle test is `tests/elfread_oracle.rs`
(`parsers_agree_on_full_symbol_maps`).

## Conditions

- Host: Linux `7.0.0-31-generic`, x86-64, warm page cache (every fixture
  fully pre-read before timing; see the runner).
- Build: `--release`, toolchain 1.98.0, goblin 0.10.7, libc 0.2.
- Date: 2026-09-17. Raw runner output is the table above (stdout).

## Re-run

```sh
cargo run -p kryprobe-privilege --example elf_spike --release
```

Exit code is nonzero if the parsers ever disagree (oracle failure).

## Deviations from the thin-spine plan

- Losers stay **unconditionally compiled** instead of
  `#[cfg(any(test, feature = "bench-alternatives"))]`: `cfg(test)` is not
  set when the library is built for integration tests, so the planned gate
  would hide the alternatives from the oracle test. The T11 `elf` suite
  consumes the same always-compiled entry points.
- goblin 0.10 (current), not 0.9: the T6a pin compiled unchanged against
  0.10.7, so the older pin had no justification.
