// SPDX-License-Identifier: GPL-3.0-or-later
//! `selftest synthetic`: the T5d script, auto-validated (exit 0 or 1).
//!
//! Runs the canonical 8-op script with the runner's pinned clock,
//! validates the JSONL structurally, renders the summary to stderr, and
//! emits JSONL to stdout (or `--out`). Two runs are byte-identical.

use kryprobe_core::ids::SessionId;
use kryprobe_core::synthetic::{SyntheticBackend, canonical_script};
use kryprobe_report::{render_summary, validate_str};
use std::io::Write;
use std::path::Path;

/// On-disk schema bytes for drift detection (mirrors `validate_file`).
fn schema_disk_bytes() -> Option<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event-v0.schema.json");
    std::fs::read(path).ok()
}

/// Runs `selftest synthetic`; validation failure is exit 1 (defect).
pub fn run(out: Option<&Path>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let backend = SyntheticBackend::new(canonical_script());
    let run = match backend.run_script(SessionId::new(1)) {
        Ok(run) => run,
        Err(err) => {
            let _ = writeln!(stderr, "selftest synthetic: backend failed: {err:?}");
            return 1;
        }
    };
    let text = run.to_jsonl();
    let Some(disk) = schema_disk_bytes() else {
        let _ = writeln!(stderr, "selftest synthetic: cannot read schema file");
        return 1;
    };
    let findings = validate_str(&text, &disk);
    if !findings.is_empty() {
        let _ = writeln!(
            stderr,
            "selftest synthetic: output failed validation (defect):"
        );
        for finding in &findings {
            let _ = writeln!(stderr, "  {finding}");
        }
        return 1;
    }
    let _ = write!(stderr, "{}", render_summary(&text));
    match out {
        Some(path) => match std::fs::write(path, &text) {
            Ok(()) => {
                let _ = writeln!(stderr, "wrote {}", path.display());
                0
            }
            Err(err) => {
                let _ = writeln!(
                    stderr,
                    "selftest synthetic: cannot write {}: {err}",
                    path.display()
                );
                1
            }
        },
        None => {
            let _ = write!(stdout, "{text}");
            0
        }
    }
}
