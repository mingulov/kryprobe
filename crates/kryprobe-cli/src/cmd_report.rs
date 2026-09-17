// SPDX-License-Identifier: GPL-3.0-or-later
//! `report`: validate a stream, then render its summary (exit 0 or 2).

use kryprobe_report::{render_summary, validate_file};
use std::io::Write;
use std::path::Path;

/// Runs `report`: findings (or an unreadable file) exit 2 with detail.
pub fn run(file: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(err) => {
            let _ = writeln!(stderr, "report: cannot read {}: {err}", file.display());
            return 2;
        }
    };
    let findings = validate_file(file);
    if !findings.is_empty() {
        let _ = writeln!(
            stderr,
            "report: {} finding(s) in {}:",
            findings.len(),
            file.display()
        );
        for finding in &findings {
            let _ = writeln!(stderr, "  {finding}");
        }
        return 2;
    }
    let _ = write!(stdout, "{}", render_summary(&text));
    0
}
