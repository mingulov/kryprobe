// SPDX-License-Identifier: GPL-3.0-or-later
//! `report`: validate a stream, then render its summary (exit 0 or 2).

use kryprobe_report::validate_and_render_file;
use std::io::Write;
use std::path::Path;

/// Runs `report`: findings (or an unreadable file) exit 2 with detail.
///
/// One streaming pass feeds both validation and rendering, so
/// million-record sessions render with bounded memory and the summary
/// always describes exactly the bytes validated (no TOCTOU window).
pub fn run(file: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (findings, summary) = validate_and_render_file(file);
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
    match summary {
        Some(summary) => {
            let _ = write!(stdout, "{summary}");
            0
        }
        // Unreachable in practice (`None` always rides an `Unreadable`
        // finding, handled above); fail closed without rendering.
        None => {
            let _ = writeln!(
                stderr,
                "report: cannot render {}: incomplete pass",
                file.display()
            );
            2
        }
    }
}
