// SPDX-License-Identifier: GPL-3.0-or-later
//! READY/GO/DONE harness: calls `spine_target_fn` argv[1] times in a loop.
//!
//! Protocol (stdio pipes): prints `READY`, waits for a `GO` line on stdin,
//! calls the target fn, prints `DONE <acc>`. The BPF pipeline test attaches
//! entry+return probes to `spine_target_fn` between READY and GO.

use std::hint::black_box;
use std::io::{BufRead, Write};

/// Probe target: out-of-line, unmangled, stable file offset.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn spine_target_fn(n: u64) -> u64 {
    black_box(n).wrapping_add(1)
}

fn main() {
    let count: u64 = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(0);
    println!("READY");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok();
    if line.trim() != "GO" {
        std::process::exit(2);
    }
    let mut acc = 0u64;
    for i in 0..count {
        acc = acc.wrapping_add(spine_target_fn(black_box(i)));
    }
    black_box(acc);
    println!("DONE {acc}");
}
