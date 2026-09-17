// SPDX-License-Identifier: GPL-3.0-or-later
//! Oracle tests: readers agree byte-for-byte, parsers agree symbol-for-symbol.

use kryprobe_privilege::elfread::{ElfBytes, FullRead, MmapGuard, goblin_parser, minimal};
use std::path::PathBuf;

const LIBC_CANDIDATES: [&str; 2] = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"];

fn own_binary() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn system_libc() -> PathBuf {
    LIBC_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            panic!(
                "system libc missing: tried {} and {}",
                LIBC_CANDIDATES[0], LIBC_CANDIDATES[1]
            )
        })
}

fn fixtures() -> Vec<PathBuf> {
    vec![own_binary(), system_libc()]
}

#[test]
fn readers_agree_byte_for_byte() {
    for path in fixtures() {
        let mmap = MmapGuard::open(&path).unwrap();
        let full = FullRead::open(&path).unwrap();
        assert_eq!(mmap.bytes(), full.bytes(), "readers disagree on {path:?}");
    }
}

#[test]
fn parsers_agree_on_full_symbol_maps() {
    for path in fixtures() {
        let reader = MmapGuard::open(&path).unwrap();
        let goblin = goblin_parser::dynamic_symbols(reader.bytes()).unwrap();
        let oracle = minimal::dynamic_symbols(reader.bytes()).unwrap();
        assert_eq!(goblin, oracle, "parsers disagree on {path:?}");
    }
}

#[test]
fn full_read_bytes_parse_identically() {
    for path in fixtures() {
        let full = FullRead::open(&path).unwrap();
        let mmap = MmapGuard::open(&path).unwrap();
        let via_full = goblin_parser::dynamic_symbols(full.bytes()).unwrap();
        let via_mmap = minimal::dynamic_symbols(mmap.bytes()).unwrap();
        assert_eq!(
            via_full, via_mmap,
            "cross reader/parser mismatch on {path:?}"
        );
    }
}

#[test]
fn printf_resolves_in_libc_stably() {
    let libc = system_libc();
    let reader = FullRead::open(&libc).unwrap();
    let first = goblin_parser::symbol_file_offset(reader.bytes(), "printf").unwrap();
    let second = goblin_parser::symbol_file_offset(reader.bytes(), "printf").unwrap();
    assert_eq!(first, second, "unstable resolution");
    assert!(first.is_some(), "printf missing in {}", libc.display());
    let oracle = minimal::symbol_file_offset(reader.bytes(), "printf").unwrap();
    assert_eq!(first, oracle, "goblin/minimal disagree on printf");
}

#[test]
fn top_level_interface_matches_minimal() {
    // Top level tracks the T6b spike winner (minimal parser).
    let libc = system_libc();
    let reader = MmapGuard::open(&libc).unwrap();
    for name in ["printf", "malloc", "main"] {
        let top = kryprobe_privilege::elfread::symbol_file_offset(reader.bytes(), name).unwrap();
        let winner = minimal::symbol_file_offset(reader.bytes(), name).unwrap();
        assert_eq!(top, winner, "top-level differs for {name}");
    }
}

#[test]
fn missing_symbol_is_none_in_both_parsers() {
    let libc = system_libc();
    let reader = FullRead::open(&libc).unwrap();
    let name = "kryprobe_no_such_symbol_xyz";
    assert_eq!(
        goblin_parser::symbol_file_offset(reader.bytes(), name).unwrap(),
        None
    );
    assert_eq!(
        minimal::symbol_file_offset(reader.bytes(), name).unwrap(),
        None
    );
}

#[test]
fn libc_symbol_map_is_nonempty() {
    let libc = system_libc();
    let reader = MmapGuard::open(&libc).unwrap();
    let map = goblin_parser::dynamic_symbols(reader.bytes()).unwrap();
    assert!(!map.is_empty(), "libc dynsym map unexpectedly empty");
}
