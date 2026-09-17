// SPDX-License-Identifier: GPL-3.0-or-later
//! elf-access spike runner (thin-spine T6 Step 3, re-run command for
//! `docs/dependencies/elf-access.md`).
//!
//! Measures the 2×2 reader×parser matrix on 3 fixtures (1 warmup + 9 timed
//! iterations, median, warm page cache) and enforces the goblin-agreement
//! oracle on every fixture: a disagreeing parser is disqualified.
//!
//! Run: `cargo run -p kryprobe-privilege --example elf_spike --release`

use kryprobe_privilege::elfread::ElfBytes;
use kryprobe_privilege::elfread::full_read::FullRead;
use kryprobe_privilege::elfread::goblin_parser;
use kryprobe_privilege::elfread::minimal;
use kryprobe_privilege::elfread::mmap::MmapGuard;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const TIMED_ITERS: usize = 9;

fn fixtures() -> Vec<(&'static str, PathBuf)> {
    let small = std::env::current_exe().expect("defect: current_exe must exist");
    let libc = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("defect: system libc fixture missing");
    let mut biggest: Option<(u64, PathBuf)> = None;
    let mut stack = vec![PathBuf::from("/usr/lib")];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Never follow symlinked dirs: /usr/lib holds links escaping
            // to /usr/include, /etc, ... (file_type is link-aware).
            let is_real_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_real_dir {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "so")
                || path.to_string_lossy().contains(".so.")
            {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if biggest.as_ref().is_none_or(|(s, _)| size > *s) {
                    biggest = Some((size, path));
                }
            }
        }
    }
    let (_, large) = biggest.expect("defect: no .so fixture under /usr/lib");
    vec![("small", small), ("libc", libc), ("large", large)]
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Time `open + full dynamic_symbols` for one reader/parser cell.
fn time_cell(
    fixture: &std::path::Path,
    reader: &str,
    parser: &str,
) -> (Duration, Vec<(String, u64)>) {
    let run_once = || -> Vec<(String, u64)> {
        let map = |bytes: &[u8]| match parser {
            "goblin" => goblin_parser::dynamic_symbols(bytes),
            "minimal" => minimal::dynamic_symbols(bytes),
            _ => unreachable!("defect: unknown parser {parser}"),
        };
        match reader {
            "mmap" => {
                let guard = MmapGuard::open(fixture).expect("defect: mmap open failed");
                map(guard.bytes()).expect("defect: parse failed")
            }
            "full_read" => {
                let full = FullRead::open(fixture).expect("defect: read open failed");
                map(full.bytes()).expect("defect: parse failed")
            }
            _ => unreachable!("defect: unknown reader {reader}"),
        }
    };
    run_once(); // warmup, untimed
    let mut samples = Vec::with_capacity(TIMED_ITERS);
    let mut last = Vec::new();
    for _ in 0..TIMED_ITERS {
        let start = Instant::now();
        last = run_once();
        samples.push(start.elapsed());
    }
    (median(samples), last)
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn main() {
    let fixtures = fixtures();
    // Warm the page cache: full byte read of every fixture before timing.
    for (_, path) in &fixtures {
        let bytes = std::fs::read(path).expect("defect: fixture unreadable");
        std::hint::black_box(bytes.len());
    }
    println!("fixture | bytes | reader | parser | median_ms (1 warmup + {TIMED_ITERS} timed)");
    let mut oracle_failed = false;
    for (name, path) in &fixtures {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let mut maps: Vec<(&str, Vec<(String, u64)>)> = Vec::new();
        for reader in ["mmap", "full_read"] {
            for parser in ["goblin", "minimal"] {
                let (med, map) = time_cell(path, reader, parser);
                println!(
                    "{name} | {size} | {reader} | {parser} | {:.3} ({} syms)",
                    ms(med),
                    map.len()
                );
                maps.push((parser, map));
            }
        }
        let first = &maps[0].1;
        for (parser, map) in &maps[1..] {
            if map != first {
                println!(
                    "ORACLE-FAIL: {name} {parser} disagrees with {} — DISQUALIFIED",
                    maps[0].0
                );
                oracle_failed = true;
            }
        }
    }
    if oracle_failed {
        std::process::exit(1);
    }
    println!("ORACLE-PASS: goblin and minimal agree on all fixtures");
}
