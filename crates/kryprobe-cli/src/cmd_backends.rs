// SPDX-License-Identifier: GPL-3.0-or-later
//! `backends`: registry states plus capability gates.
//!
//! The registry owns the synthetic backend (no `Box::leak`); the `active`
//! row is backed by a live end-to-end driver pass (detect → plan →
//! configure → decode → finalize) over one synthetic event. A driver
//! failure fails closed (stderr plus exit 1) instead of claiming `active`.
//! The other three rows are static thin-spine states shared with
//! [`crate::cmd_doctor`].

use kryprobe_core::backend::{BackendDriver, BackendRegistry, RawEvent};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
use kryprobe_core::synthetic::SyntheticBackend;
use std::io::Write;

/// One backend state row.
pub struct BackendRow {
    /// Backend id (`synthetic`, `p11`, `openssl`, `kcrypto`).
    pub id: &'static str,
    /// State word (`active`, `not installed`, `unavailable`).
    pub state: &'static str,
    /// Parenthesized qualifier, if any.
    pub note: Option<&'static str>,
}

/// The four thin-spine backend rows (plan-exact wording).
pub fn backend_rows() -> [BackendRow; 4] {
    [
        BackendRow {
            id: "synthetic",
            state: "active",
            note: Some("test-only"),
        },
        BackendRow {
            id: "p11",
            state: "not installed",
            note: None,
        },
        BackendRow {
            id: "openssl",
            state: "not installed",
            note: None,
        },
        BackendRow {
            id: "kcrypto",
            state: "unavailable",
            note: Some("no backend; needs target BTF when implemented"),
        },
    ]
}

/// Human row: `id: state` plus an optional `(note)` qualifier.
pub fn human_row(row: &BackendRow) -> String {
    match row.note {
        Some(note) => format!("{}: {} ({note})", row.id, row.state),
        None => format!("{}: {}", row.id, row.state),
    }
}

/// Minimal host facts for the liveness proof: synthetic requires nothing,
/// so all gates read false and the proof passes on any host.
fn proof_runtime() -> RuntimeCapabilities {
    RuntimeCapabilities {
        kernel_release: String::from("synthetic"),
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf_present: false,
        userns: false,
        yama_scope: 0,
        caps: Vec::new(),
    }
}

/// Synthetic capability gates from a live owned registry (deterministic).
///
/// Proves liveness first: one driver pass over one synthetic event must
/// yield exactly one observation and one summary with no skips. Any driver
/// failure (or partial result, a defect) is `Err` and the caller fails
/// closed instead of printing the `active` row.
fn live_synthetic_gates() -> Result<[(&'static str, bool); 4], String> {
    let mut registry = BackendRegistry::new();
    // Fresh registry + unique id: registration is infallible by construction.
    registry
        .register(Box::new(SyntheticBackend::new(Vec::new())))
        .expect("fresh registry accepts synthetic");
    let mut driver = BackendDriver::harness();
    let (header, payload) = SyntheticBackend::harness_event(
        EvidencePhase::Entered,
        OperationClass::Sign,
        CallKind::Operation,
        0,
        1_000_000,
    );
    let events = [RawEvent {
        header,
        payload: &payload,
    }];
    let report = driver
        .run(&registry, &proof_runtime(), &events)
        .map_err(|err| err.to_string())?;
    if report.observations.len() != 1 || report.summaries.len() != 1 || !report.skipped.is_empty() {
        return Err(String::from(
            "defect: synthetic liveness pass returned partial results",
        ));
    }
    let backend = registry
        .get(BackendId::Synthetic)
        .expect("synthetic registered");
    let required = &backend.capabilities().required;
    Ok([
        ("uprobe_multi", required.uprobe_multi),
        ("cookies", required.cookies),
        ("ringbuf", required.ringbuf),
        ("btf", required.btf),
    ])
}

/// Runs `backends`; exit 0, or 1 when the synthetic liveness proof fails.
pub fn run(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let gates = match live_synthetic_gates() {
        Ok(gates) => gates,
        Err(err) => {
            let _ = writeln!(stderr, "backends: synthetic liveness proof failed: {err}");
            return 1;
        }
    };
    let rows = backend_rows();
    if json {
        let caps = serde_json::json!({
            "uprobe_multi": gates[0].1,
            "cookies": gates[1].1,
            "ringbuf": gates[2].1,
            "btf": gates[3].1,
        });
        let backends: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "state": row.state,
                    "note": row.note,
                    "capabilities": if row.id == "synthetic" { Some(&caps) } else { None },
                })
            })
            .collect();
        let _ = writeln!(stdout, "{}", serde_json::json!({ "backends": backends }));
        return 0;
    }
    for row in &rows {
        let _ = writeln!(stdout, "{}", human_row(row));
        if row.id == "synthetic" {
            let gates = gates
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(stdout, "  requires: {gates}");
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_proof_yields_all_false_synthetic_gates() {
        let gates = live_synthetic_gates().expect("synthetic liveness proof runs clean");
        assert_eq!(
            gates,
            [
                ("uprobe_multi", false),
                ("cookies", false),
                ("ringbuf", false),
                ("btf", false),
            ]
        );
    }

    #[test]
    fn run_exits_zero_with_requires_line() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(run(false, &mut stdout, &mut stderr), 0);
        let stdout = String::from_utf8(stdout).expect("stdout utf-8");
        assert!(stdout.contains("synthetic: active (test-only)"), "{stdout}");
        assert!(stdout.contains("requires:"), "{stdout}");
        assert!(stderr.is_empty());
    }
}
