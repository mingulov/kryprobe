// SPDX-License-Identifier: GPL-3.0-or-later
//! Elf suite: T6b 2×2 access×parse matrix re-run (median of 5, 1 warmup).
//!
//! Workload per cell iteration matches T6b (open + full dynamic-symbol
//! map); fixtures are the bench binary itself plus system libc. The 138MB
//! libLLVM fixture is deliberately skipped (too large for a routine lane;
//! T6b covers it). The oracle comparison stays live: parser disagreement
//! denies the suite. `still_fastest` records whether mmap+minimal wins
//! every fixture (ties count); the smoke test only asserts row presence.

use super::{SuiteResult, SuiteStatus, median_of};
use kryprobe_privilege::elfread::{ElfBytes, FullRead, MmapGuard, goblin_parser, minimal};
use std::path::PathBuf;
use std::time::Instant;

/// Measured iterations after warmup, per cell.
const ITERS: usize = 5;
/// Cell order in rows and JSON arrays.
const CELLS: [&str; 4] = [
    "mmap+goblin",
    "mmap+minimal",
    "full_read+goblin",
    "full_read+minimal",
];
/// Recorded T6b winner cell.
const WINNER: &str = "mmap+minimal";
/// System libc candidates (mirrors the oracle test).
const LIBC_CANDIDATES: [&str; 2] = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"];

fn denied(stage: impl Into<String>) -> SuiteResult {
    SuiteResult {
        name: "elf",
        status: SuiteStatus::Denied {
            stage: stage.into(),
        },
    }
}

fn system_libc() -> Option<PathBuf> {
    LIBC_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// One cell iteration: open via `mmap` xor full-read, then parse fully.
fn cell_once(fixture: &PathBuf, mmap: bool, minimal_parse: bool) -> Result<f64, String> {
    let start = Instant::now();
    if mmap {
        let guard = MmapGuard::open(fixture).map_err(|err| format!("open:{err}"))?;
        parse(guard.bytes(), minimal_parse)?;
    } else {
        let full = FullRead::open(fixture).map_err(|err| format!("open:{err}"))?;
        parse(full.bytes(), minimal_parse)?;
    }
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn parse(bytes: &[u8], minimal_parse: bool) -> Result<Vec<(String, u64)>, String> {
    if minimal_parse {
        minimal::dynamic_symbols(bytes).map_err(|err| format!("parse:{err}"))
    } else {
        goblin_parser::dynamic_symbols(bytes).map_err(|err| format!("parse:{err}"))
    }
}

/// Median milliseconds for one cell (1 warmup + 5 measured).
fn cell_median(fixture: &PathBuf, mmap: bool, minimal_parse: bool) -> Result<f64, String> {
    cell_once(fixture, mmap, minimal_parse)?;
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        samples.push(cell_once(fixture, mmap, minimal_parse)?);
    }
    Ok(median_of(&mut samples))
}

/// Runs the elf suite over the available fixtures.
pub(crate) fn run() -> SuiteResult {
    let mut fixtures: Vec<(&str, PathBuf)> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        fixtures.push(("self", exe));
    }
    if let Some(libc) = system_libc() {
        fixtures.push(("libc", libc));
    }
    if fixtures.is_empty() {
        return denied("missing-fixture");
    }
    // Live oracle: parsers must still agree on every fixture.
    for (name, fixture) in &fixtures {
        let guard = match MmapGuard::open(fixture) {
            Ok(guard) => guard,
            Err(err) => return denied(format!("open:{err}")),
        };
        let goblin = match goblin_parser::dynamic_symbols(guard.bytes()) {
            Ok(map) => map,
            Err(err) => return denied(format!("parse:{err}")),
        };
        let minimal = match minimal::dynamic_symbols(guard.bytes()) {
            Ok(map) => map,
            Err(err) => return denied(format!("parse:{err}")),
        };
        if goblin != minimal {
            return denied(format!("oracle-mismatch:{name}"));
        }
    }
    let mut rows: Vec<String> = Vec::new();
    let mut json_fixtures = serde_json::Map::new();
    let mut still_fastest = true;
    for (name, fixture) in &fixtures {
        let mut medians = Vec::with_capacity(4);
        for (mmap, minimal_parse) in [(true, false), (true, true), (false, false), (false, true)] {
            match cell_median(fixture, mmap, minimal_parse) {
                Ok(median) => medians.push(median),
                Err(stage) => return denied(stage),
            }
        }
        let best = medians.iter().fold(f64::INFINITY, |a, b| a.min(*b));
        still_fastest &= medians[1] <= best;
        rows.push(format!(
            "{name}=[{:.3},{:.3},{:.3},{:.3}]ms",
            medians[0], medians[1], medians[2], medians[3]
        ));
        json_fixtures.insert((*name).to_owned(), serde_json::json!(medians));
    }
    SuiteResult {
        name: "elf",
        status: SuiteStatus::Ok {
            human: format!(
                "still_fastest={still_fastest} {} order={}",
                rows.join(" "),
                CELLS.join(",")
            ),
            json: serde_json::json!({
                "still_fastest": still_fastest,
                "winner": WINNER,
                "cells": CELLS,
                "fixtures": json_fixtures,
            }),
        },
    }
}
