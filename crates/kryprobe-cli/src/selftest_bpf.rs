// SPDX-License-Identifier: GPL-3.0-or-later
//! `selftest bpf`: T7 pipeline as JSONL + summary (exit 0/1/3/4).
//!
//! The JSONL carries session start/end only: per-event observations and
//! backend-attributed snapshots would claim coverage the kprobe lane has
//! no backend for. Loss surfaces through the verdict (`PARTIAL`), the
//! stderr reconcile marker, and exit 4 (partial) — never silently.

use crate::cmd_selftest::{locate_bpf_object, sibling_binary};
use kryprobe_core::ReconcileVerdict;
use kryprobe_core::enums::{CaptureMode, TargetSelector};
use kryprobe_privilege::bpfselftest::{BpfSelftestConfig, BpfSelftestError, run_bpf_selftest};
use kryprobe_report::{FinalBarrier, JsonlWriter, SessionEnd, SessionStart, SessionVerdict};
use std::io::Write;
use std::path::Path;

fn emit_jsonl(
    calls: u64,
    verdict: SessionVerdict,
    exit_code: Option<i32>,
    signal: Option<i32>,
) -> String {
    let mut writer = JsonlWriter::new("session:bpf-selftest");
    // Backends unclaimable here (no crypto backend observed); the start
    // record carries an empty request list by design, never a guess.
    writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::OwnedRun,
            capture_mode: CaptureMode::Trace,
            requested_backends: Vec::new(),
            qualification_id: format!("qualification:bpf-selftest-{calls}"),
        })
        .expect("bpf start record");
    writer
        .session_end(&SessionEnd {
            verdict,
            final_barrier: FinalBarrier::Validated,
            unresolved_gap_ids: Vec::new(),
            child_exit_code: exit_code,
            child_signal: signal,
        })
        .expect("bpf end record");
    writer.into_string()
}

/// Runs `selftest bpf`: 0 clean, 4 partial, 3 denied/missing, 1 failure.
pub fn run(calls: u64, out: Option<&Path>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Some(object) = locate_bpf_object() else {
        let _ = writeln!(
            stderr,
            "selftest bpf: missing object (run `cargo xtask build --bpf`)"
        );
        return 3;
    };
    let Some(fixture) = sibling_binary("spine_fixture", "KRYPROBE_FIXTURE") else {
        let _ = writeln!(stderr, "selftest bpf: missing spine_fixture sibling");
        return 3;
    };
    let outcome = match run_bpf_selftest(&BpfSelftestConfig {
        calls,
        object,
        fixture,
    }) {
        Ok(outcome) => outcome,
        Err(BpfSelftestError::Denied { stage, errno }) => {
            let _ = writeln!(
                stderr,
                "selftest bpf: Denied{{{stage}}} (errno {errno}); needs privilege"
            );
            return 3;
        }
        Err(BpfSelftestError::MissingArtifact { what, path }) => {
            let _ = writeln!(stderr, "selftest bpf: missing {what} at {}", path.display());
            return 3;
        }
        Err(err) => {
            let _ = writeln!(stderr, "selftest bpf: {err}");
            return 1;
        }
    };
    let counts_ok = outcome.entries == calls && outcome.returns == calls;
    let (marker, verdict, code) = match (&outcome.verdict, counts_ok) {
        (ReconcileVerdict::Clean, true) => ("clean", SessionVerdict::Observed, 0),
        (ReconcileVerdict::Partial { missing }, _) => {
            let _ = writeln!(
                stderr,
                "selftest bpf: partial ({missing} missing; ring={} drop={} queue={})",
                outcome.ring, outcome.dropped, outcome.queue_drops
            );
            ("partial", SessionVerdict::Partial, 4)
        }
        (ReconcileVerdict::Clean, false) | (ReconcileVerdict::Defect { .. }, _) => {
            ("defect", SessionVerdict::Failed, 1)
        }
    };
    let text = emit_jsonl(calls, verdict, outcome.exit_code, outcome.signal);
    let _ = write!(stderr, "{}", kryprobe_report::render_summary(&text));
    let _ = writeln!(
        stderr,
        "selftest bpf: entries={} returns={} received={} ring={} drop={} queue={}",
        outcome.entries,
        outcome.returns,
        outcome.received,
        outcome.ring,
        outcome.dropped,
        outcome.queue_drops
    );
    let _ = writeln!(stderr, "reconcile: {marker}");
    match out {
        Some(path) => match std::fs::write(path, &text) {
            Ok(()) => {
                let _ = writeln!(stderr, "wrote {}", path.display());
                code
            }
            Err(err) => {
                let _ = writeln!(
                    stderr,
                    "selftest bpf: cannot write {}: {err}",
                    path.display()
                );
                1
            }
        },
        None => {
            let _ = write!(stdout, "{text}");
            code
        }
    }
}
