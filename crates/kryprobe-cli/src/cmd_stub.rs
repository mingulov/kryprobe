// SPDX-License-Identifier: GPL-3.0-or-later
//! Thin-spine stubs: `plan`, `observe`, `run` (always exit 3).

use std::io::Write;

/// Runs a stub: names itself honestly and exits 3.
pub fn run(name: &str, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(
        stderr,
        "unsupported-in-thin-spine: '{name}' is not implemented in thin spine"
    );
    3
}
