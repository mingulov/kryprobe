// SPDX-License-Identifier: GPL-3.0-or-later
//! Differential properties: the hand-rolled `minimal` ELF parser against the
//! `goblin` reference (audit #4). Panics fail as counterexamples, so these
//! also pin the never-panic (#6 class) rule.
//!
//! Contract (verified by sweep, see below): on corrupt inputs the parsers may
//! legitimately differ in ACCEPTANCE (minimal skips per-symbol where goblin
//! rejects per-file, e.g. non-UTF8 names; symbol counts derive from different
//! sources), but minimal never FABRICATES: every pair it returns is identical
//! in goblin's map whenever goblin accepts. Exact equality on valid inputs is
//! pinned by `elfread_oracle.rs` fixtures.

use kryprobe_privilege::elfread::{goblin_parser, minimal};
use proptest::prelude::*;
use std::collections::HashSet;

const LIBC_CANDIDATES: [&str; 2] = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"];

/// Stable mutation base (the test binary's own bytes shift on every edit).
fn base_elf() -> Vec<u8> {
    let path = LIBC_CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or_else(|| panic!("system libc missing for mutation base"));
    std::fs::read(path).unwrap()
}

/// No fabrication: minimal's pairs are a subset of goblin's when both accept.
fn subset_holds(bytes: &[u8]) -> Result<(), TestCaseError> {
    if let (Ok(mine), Ok(theirs)) = (
        minimal::dynamic_symbols(bytes),
        goblin_parser::dynamic_symbols(bytes),
    ) {
        let set: HashSet<_> = theirs.into_iter().collect();
        for pair in &mine {
            prop_assert!(set.contains(pair), "fabricated pair {pair:?}");
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes: mostly rejections + no-panic (the #6 shape).
    #[test]
    fn arbitrary_bytes_never_panic_and_never_fabricate(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        subset_holds(&bytes)?;
    }

    /// Mutated real ELF: many accepted inputs, genuine oracle exercise.
    #[test]
    fn mutated_elf_never_fabricates(
        seed in any::<u64>(),
        nmuts in 0..6usize,
        trunc in prop::option::of(0usize..4096),
    ) {
        let mut bytes = base_elf();
        // Deterministic xorshift from the seed: reproducible failures.
        let mut st = seed | 1;
        let mut next = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..nmuts {
            let i = (next() % bytes.len() as u64) as usize;
            bytes[i] = (next() & 0xff) as u8;
        }
        if let Some(t) = trunc {
            bytes.truncate(t.min(bytes.len()));
        }
        subset_holds(&bytes)?;
    }
}
