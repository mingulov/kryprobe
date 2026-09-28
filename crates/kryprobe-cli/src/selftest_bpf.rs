// SPDX-License-Identifier: GPL-3.0-or-later
//! `selftest bpf`: T7 pipeline as JSONL + summary (exit 0/1/3/4).
//!
//! The JSONL carries session start/end only: per-event observations and
//! backend-attributed snapshots would claim coverage the kprobe lane has
//! no backend for. Loss surfaces through the verdict (`PARTIAL`), the
//! stderr reconcile marker, and exit 3 (partial) — never silently.

use crate::cmd_selftest::{locate_bpf_object, sibling_binary};
use kryprobe_core::ReconcileVerdict;
use kryprobe_core::enums::{CaptureMode, TargetSelector};
use kryprobe_privilege::bpfselftest::{BpfSelftestConfig, BpfSelftestError, run_bpf_selftest};
use kryprobe_report::{
    FinalBarrier, JsonlWriter, ReportError, SessionEnd, SessionStart, SessionVerdict,
    write_str_atomic,
};
use std::io::Write;
use std::path::Path;

fn emit_jsonl(
    calls: u64,
    verdict: SessionVerdict,
    exit_code: Option<i32>,
    signal: Option<i32>,
) -> Result<String, ReportError> {
    let mut writer = JsonlWriter::new("session:bpf-selftest");
    // Backends unclaimable here (no crypto backend observed); the start
    // record carries an empty request list by design, never a guess.
    writer.session_start(&SessionStart {
        target_selector: TargetSelector::OwnedRun,
        capture_mode: CaptureMode::Trace,
        requested_backends: Vec::new(),
        qualification_id: format!("qualification:bpf-selftest-{calls}"),
    })?;
    writer.session_end(&SessionEnd {
        verdict,
        final_barrier: FinalBarrier::Validated,
        unresolved_gap_ids: Vec::new(),
        child_exit_code: exit_code,
        child_signal: signal,
    })?;
    Ok(writer.into_string())
}

/// Terminal marker for one selftest run: the stderr `reconcile:`
/// word, the session verdict, and the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelftestMarker {
    /// Every call observed exactly (exit 0).
    Clean,
    /// Ran with receipted coverage gaps (exit 3).
    Partial {
        /// Ground truth minus delivered records.
        missing: u64,
    },
    /// Over-accounted or unaccounted evidence (exit 1).
    Defect,
}

/// Maps the loss-ledger verdict + per-kind counts to the terminal
/// marker. Fully-accounted loss (a `Clean` ledger with drops > 0 —
/// every missing record receipted by a ring/guard/truncation
/// counter) is PARTIAL: the run is short evidence, not corrupt
/// evidence. Only over-accounting (`Defect`) or a kind split wrong
/// with nothing accounted (drops == 0 — duplication or corruption,
/// since genuine loss always lands in a counter) is a defect.
fn classify_selftest(
    verdict: &ReconcileVerdict,
    entries: u64,
    returns: u64,
    calls: u64,
    drops: u64,
) -> SelftestMarker {
    let counts_ok = entries == calls && returns == calls;
    match (verdict, counts_ok) {
        (ReconcileVerdict::Clean, true) => SelftestMarker::Clean,
        (ReconcileVerdict::Partial { missing }, _) => SelftestMarker::Partial { missing: *missing },
        (ReconcileVerdict::Clean, false) if drops > 0 => {
            // A `Clean` ledger reconciles exactly
            // (received + drops == 2·calls), so the shortfall IS the
            // accounted drops — short evidence, never corrupt.
            let received = entries.saturating_add(returns);
            SelftestMarker::Partial {
                missing: calls.saturating_mul(2).saturating_sub(received),
            }
        }
        (ReconcileVerdict::Clean, false) | (ReconcileVerdict::Defect { .. }, _) => {
            SelftestMarker::Defect
        }
    }
}

/// Runs `selftest bpf`: 0 clean, 3 partial, 4 denied/missing, 1 failure.
pub fn run(calls: u64, out: Option<&Path>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Some(object) = locate_bpf_object() else {
        let _ = writeln!(
            stderr,
            "selftest bpf: missing object (run `cargo xtask build --bpf`)"
        );
        return 4;
    };
    let Some(fixture) = sibling_binary("spine_fixture", "KRYPROBE_FIXTURE") else {
        let _ = writeln!(stderr, "selftest bpf: missing spine_fixture sibling");
        return 4;
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
            return 4;
        }
        Err(BpfSelftestError::MissingArtifact { what, path }) => {
            let _ = writeln!(stderr, "selftest bpf: missing {what} at {}", path.display());
            return 4;
        }
        Err(err) => {
            let _ = writeln!(stderr, "selftest bpf: {err}");
            return 1;
        }
    };
    let drops = outcome
        .ring
        .saturating_add(outcome.dropped)
        .saturating_add(outcome.truncated);
    let (marker, verdict, code) = match classify_selftest(
        &outcome.verdict,
        outcome.entries,
        outcome.returns,
        calls,
        drops,
    ) {
        SelftestMarker::Clean => ("clean", SessionVerdict::Observed, 0),
        SelftestMarker::Partial { missing } => {
            let _ = writeln!(
                stderr,
                "selftest bpf: partial ({missing} missing; ring={} drop={} trunc={} queue={})",
                outcome.ring, outcome.dropped, outcome.truncated, outcome.queue_drops
            );
            ("partial", SessionVerdict::Partial, 3)
        }
        SelftestMarker::Defect => ("defect", SessionVerdict::Failed, 1),
    };
    let text = match emit_jsonl(calls, verdict, outcome.exit_code, outcome.signal) {
        Ok(text) => text,
        Err(err) => {
            let _ = writeln!(stderr, "selftest bpf: cannot encode session jsonl: {err}");
            return 1;
        }
    };
    let _ = write!(stderr, "{}", kryprobe_report::render_summary(&text));
    let _ = writeln!(
        stderr,
        "selftest bpf: entries={} returns={} received={} ring={} drop={} trunc={} queue={}",
        outcome.entries,
        outcome.returns,
        outcome.received,
        outcome.ring,
        outcome.dropped,
        outcome.truncated,
        outcome.queue_drops
    );
    let _ = writeln!(stderr, "reconcile: {marker}");
    match out {
        Some(path) => match write_str_atomic(path, &text) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_jsonl_rejects_out_of_range_exit_and_signal() {
        assert_eq!(
            emit_jsonl(2, SessionVerdict::Observed, Some(999), None),
            Err(ReportError::ExitCodeOutOfRange(999))
        );
        assert_eq!(
            emit_jsonl(2, SessionVerdict::Observed, Some(-1), None),
            Err(ReportError::ExitCodeOutOfRange(-1))
        );
        assert_eq!(
            emit_jsonl(2, SessionVerdict::Observed, None, Some(999)),
            Err(ReportError::SignalOutOfRange(999))
        );
        assert_eq!(
            emit_jsonl(2, SessionVerdict::Observed, None, Some(0)),
            Err(ReportError::SignalOutOfRange(0))
        );
    }

    /// P7/T12 verdict table (item 5 root cause, second leg):
    /// fully-accounted loss is PARTIAL, not a defect. The historical
    /// row replays `evidence/0-4/priv-cli_bpf_e2e.txt` (entries=18716
    /// returns=18717 ring=2567 over 20000 calls — ledger Clean, kind
    /// split asymmetric): every missing record is receipted by the
    /// ring counter, so the honest marker is partial with missing ==
    /// 2567. A wrong kind split with NOTHING accounted (drops == 0)
    /// stays a defect — genuine loss always lands in a counter, so
    /// that shape means duplication or corruption.
    #[test]
    fn classify_selftest_table() {
        use ReconcileVerdict::{Clean, Defect, Partial};
        // Healthy run: exact counts, no loss.
        assert_eq!(
            classify_selftest(&Clean, 20000, 20000, 20000, 0),
            SelftestMarker::Clean
        );
        // Historical 2026-09-19 row: accounted ring loss with a
        // boundary-asymmetric kind split → partial, missing == drops.
        assert_eq!(
            classify_selftest(&Clean, 18716, 18717, 20000, 2567),
            SelftestMarker::Partial { missing: 2567 }
        );
        // Single pressured record: one return ring-dropped.
        assert_eq!(
            classify_selftest(&Clean, 20000, 19999, 20000, 1),
            SelftestMarker::Partial { missing: 1 }
        );
        // Unaccounted shortfall (silent loss): the ledger's own
        // missing rides through.
        assert_eq!(
            classify_selftest(&Partial { missing: 5 }, 19995, 20000, 20000, 0),
            SelftestMarker::Partial { missing: 5 }
        );
        // Wrong kind split with nothing accounted: duplication or
        // corruption, still a defect.
        assert_eq!(
            classify_selftest(&Clean, 20001, 19999, 20000, 0),
            SelftestMarker::Defect
        );
        // Over-accounted ledger: always a defect.
        assert_eq!(
            classify_selftest(&Defect { excess: 2 }, 20000, 20000, 20000, 2),
            SelftestMarker::Defect
        );
    }

    #[test]
    fn emit_jsonl_accepts_boundary_values() {
        assert!(emit_jsonl(2, SessionVerdict::Observed, Some(0), Some(1)).is_ok());
        assert!(emit_jsonl(2, SessionVerdict::Observed, Some(255), Some(128)).is_ok());
        assert!(emit_jsonl(2, SessionVerdict::Observed, None, None).is_ok());
    }
}
