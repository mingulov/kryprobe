// SPDX-License-Identifier: GPL-3.0-or-later
//! `selftest synthetic`: the T5d script, auto-validated (exit 0 or 1).
//!
//! Runs the canonical 8-op script with the runner's pinned clock,
//! validates the JSONL structurally, renders the summary to stderr, and
//! emits JSONL to stdout (or `--out`). Two runs are byte-identical.

use kryprobe_core::ids::{IdIssuer, SessionId};
use kryprobe_core::synthetic::{SyntheticBackend, canonical_script};
use kryprobe_report::{
    ResolvedSchema, render_summary, resolve_schema, validate_str, write_str_atomic,
};
use std::io::Write;
use std::path::Path;

/// Runs `selftest synthetic`; validation failure is exit 1 (defect).
pub fn run(out: Option<&Path>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_with_schema(out, stdout, stderr, &resolve_schema())
}

/// [`run`] with an explicit resolved schema (test seam: installed binaries
/// have no on-disk copy, so tests pass [`ResolvedSchema::Embedded`]).
fn run_with_schema(
    out: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    resolved: &ResolvedSchema,
) -> i32 {
    let backend = SyntheticBackend::new(canonical_script());
    let issuer = IdIssuer::default();
    let run = match backend.run_script(SessionId::new(1), &issuer) {
        Ok(run) => run,
        Err(err) => {
            let _ = writeln!(stderr, "selftest synthetic: backend failed: {err:?}");
            return 1;
        }
    };
    let text = run.to_jsonl();
    let Some(bytes) = resolved.bytes() else {
        let _ = writeln!(stderr, "selftest synthetic: cannot read schema file");
        return 1;
    };
    let findings = validate_str(&text, bytes);
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
        Some(path) => match write_str_atomic(path, &text) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_report::resolve_schema_at;

    fn missing_schema_path() -> std::path::PathBuf {
        let missing = std::env::temp_dir()
            .join(format!("kryprobe-synth-absent-{}", std::process::id()))
            .join("event-v0.schema.json");
        assert!(!missing.exists(), "defect: {missing:?} unexpectedly exists");
        missing
    }

    #[test]
    fn absent_schema_runs_clean() {
        // Installed-binary simulation: no on-disk copy resolves embed-only,
        // so the synth run validates clean and exits 0.
        let resolved = resolve_schema_at(&missing_schema_path());
        assert_eq!(resolved, ResolvedSchema::Embedded);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_schema(None, &mut stdout, &mut stderr, &resolved);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&stderr));
        assert!(!stdout.is_empty(), "synth must emit JSONL");
    }

    #[test]
    fn out_writes_atomically_with_no_tmp_litter() {
        let resolved = resolve_schema_at(&missing_schema_path());
        assert_eq!(resolved, ResolvedSchema::Embedded);
        // Baseline: stdout bytes for the same run.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_schema(None, &mut stdout, &mut stderr, &resolved);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&stderr));
        // `--out` commits the identical bytes atomically.
        let scratch = kryprobe_testkit::TempDir::named("synth-out").expect("temp dir");
        let path = scratch.path().join("synth.jsonl");
        let mut file_stdout = Vec::new();
        let mut file_stderr = Vec::new();
        let code = run_with_schema(Some(&path), &mut file_stdout, &mut file_stderr, &resolved);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&file_stderr));
        assert_eq!(std::fs::read(&path).expect("read back"), stdout);
        assert!(file_stdout.is_empty(), "file run writes no stdout");
        let litter: Vec<_> = std::fs::read_dir(scratch.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(litter.is_empty(), "tmp litter: {litter:?}");
    }

    #[test]
    fn unreadable_schema_fails_closed() {
        // Present-but-unreadable (a directory) still exits 1, as before.
        let resolved = resolve_schema_at(&std::env::temp_dir());
        assert_eq!(resolved, ResolvedSchema::Unreadable);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_schema(None, &mut stdout, &mut stderr, &resolved);
        assert_eq!(code, 1);
        let stderr = String::from_utf8(stderr).expect("stderr utf-8");
        assert!(
            stderr.contains("cannot read schema file"),
            "stderr: {stderr}"
        );
    }
}
