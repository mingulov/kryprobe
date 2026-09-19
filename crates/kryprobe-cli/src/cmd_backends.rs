// SPDX-License-Identifier: GPL-3.0-or-later
//! `backends`: registry states plus capability gates.
//!
//! The registry owns the synthetic backend (no `Box::leak`); the `active`
//! row is backed by a live end-to-end driver pass (detect → plan →
//! configure → decode → finalize) over one synthetic event. A driver
//! failure fails closed (stderr plus exit 1) instead of claiming `active`.
//! The p11/openssl rows are static thin-spine states shared with
//! [`crate::cmd_doctor`]; the kcrypto row is live via an unprivileged
//! detect+plan pass ([`live_kcrypto_gates`], no attach).

use kryprobe_core::backend::{
    BackendDriver, BackendRegistry, DetectContext, PlanContext, RawEvent,
};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{BackendId, CallKind, CaptureMode, EvidencePhase, OperationClass};
use kryprobe_core::ids::SessionId;
use kryprobe_core::plan::CapabilityRequirements;
use kryprobe_core::synthetic::SyntheticBackend;
use kryprobe_privilege::ProbeOutcome;
use kryprobe_privilege::kcrypto_backend::register_kcrypto;
use kryprobe_privilege::probe::btf_present;
use std::io::Write;

/// One backend state row.
pub struct BackendRow {
    /// Backend id (`synthetic`, `p11`, `openssl`, `kcrypto`).
    pub id: &'static str,
    /// State word (`active`, `not installed`, `available`, `degraded`,
    /// `unavailable`).
    pub state: &'static str,
    /// Parenthesized qualifier, if any (static text or a live gate/error).
    pub note: Option<String>,
}

/// Live kcrypto facts from one unprivileged detect+plan pass (D12).
pub struct LiveKcrypto {
    /// Row state: `available`, `degraded`, or `unavailable`.
    pub state: &'static str,
    /// `None` when available; the failing gate(s) when degraded; the exact
    /// detect error when unavailable.
    pub note: Option<String>,
    /// Capability gates in synthetic order (plan `required` echo).
    pub gates: [(&'static str, bool); 4],
}

/// The four backend rows: synthetic/p11/openssl static, kcrypto live. A
/// kcrypto gating defect (impossible by construction — detect+plan are
/// total over the system instance) renders as `unavailable` with the
/// defect as its note, never a panic (`doctor` always renders exit 0).
pub fn backend_rows() -> [BackendRow; 4] {
    let live = live_kcrypto_gates().unwrap_or_else(|defect| LiveKcrypto {
        state: "unavailable",
        note: Some(defect),
        gates: [
            ("uprobe_multi", false),
            ("cookies", false),
            ("ringbuf", false),
            ("btf", false),
        ],
    });
    backend_rows_with(&live)
}

/// Rows for one already-probed [`LiveKcrypto`] (single detect pass).
fn backend_rows_with(live: &LiveKcrypto) -> [BackendRow; 4] {
    [
        BackendRow {
            id: "synthetic",
            state: "active",
            note: Some(String::from("test-only")),
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
            state: live.state,
            note: live.note.clone(),
        },
    ]
}

/// Human row: `id: state` plus an optional `(note)` qualifier.
pub fn human_row(row: &BackendRow) -> String {
    match &row.note {
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

/// Gate-check-only runtime: only `btf_present` is probed live (the sole
/// kcrypto gate, `required = { btf: true }`); every other field is unset
/// and must never be displayed — `satisfies` reads required flags only.
fn gate_runtime() -> RuntimeCapabilities {
    let btf = matches!(btf_present(), ProbeOutcome::Pass { .. });
    RuntimeCapabilities {
        kernel_release: String::from("backends-gate-check"),
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf_present: btf,
        userns: false,
        yama_scope: 0,
        caps: Vec::new(),
    }
}

/// Required flags in synthetic gate order.
fn gates_from(required: &CapabilityRequirements) -> [(&'static str, bool); 4] {
    [
        ("uprobe_multi", required.uprobe_multi),
        ("cookies", required.cookies),
        ("ringbuf", required.ringbuf),
        ("btf", required.btf),
    ]
}

/// Required gates the runtime fails, in gate order (empty ⟺ satisfied).
fn failing_gates(
    required: &CapabilityRequirements,
    runtime: &RuntimeCapabilities,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if required.uprobe_multi && !runtime.uprobe_multi {
        out.push("uprobe_multi");
    }
    if required.cookies && !runtime.cookies {
        out.push("cookies");
    }
    if required.ringbuf && !runtime.ringbuf {
        out.push("ringbuf");
    }
    if required.btf && !runtime.btf_present {
        out.push("btf");
    }
    out
}

/// Live kcrypto gates (D12): fresh registry, `register_kcrypto`, detect,
/// then plan only (no attach) — proves wiring unprivileged. Detect
/// failure is row data (`unavailable` + exact error); the `Err` arm is a
/// defect (empty detect / plan refusal, impossible by construction) and
/// the caller fails closed like the synthetic proof.
pub fn live_kcrypto_gates() -> Result<LiveKcrypto, String> {
    let mut registry = BackendRegistry::new();
    // Fresh registry + unique id: registration is infallible by construction.
    register_kcrypto(&mut registry).expect("fresh registry accepts kcrypto");
    let backend = registry
        .get(BackendId::KCrypto)
        .expect("kcrypto registered");
    let runtime = gate_runtime();
    let session = SessionId::new(1);
    let detect_ctx = DetectContext {
        session,
        runtime: &runtime,
    };
    let instances = match backend.detect(&detect_ctx) {
        Ok(instances) => instances,
        Err(err) => {
            return Ok(LiveKcrypto {
                state: "unavailable",
                note: Some(err.to_string()),
                gates: gates_from(&backend.capabilities().required),
            });
        }
    };
    let instance = instances
        .first()
        .ok_or_else(|| String::from("defect: kcrypto detect returned no instance"))?;
    let plan_ctx = PlanContext {
        session,
        runtime: &runtime,
    };
    let plan = backend
        .plan(&plan_ctx, instance, CaptureMode::Profile)
        .map_err(|err| err.to_string())?;
    let gates = gates_from(&plan.required);
    if runtime.satisfies(&plan.required) {
        Ok(LiveKcrypto {
            state: "available",
            note: None,
            gates,
        })
    } else {
        Ok(LiveKcrypto {
            state: "degraded",
            note: Some(format!(
                "needs {}",
                failing_gates(&plan.required, &runtime).join(",")
            )),
            gates,
        })
    }
}

/// Runs `backends`; exit 0, or 1 when a liveness proof fails.
pub fn run(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let gates = match live_synthetic_gates() {
        Ok(gates) => gates,
        Err(err) => {
            let _ = writeln!(stderr, "backends: synthetic liveness proof failed: {err}");
            return 1;
        }
    };
    let live = match live_kcrypto_gates() {
        Ok(live) => live,
        Err(err) => {
            let _ = writeln!(stderr, "backends: kcrypto gates failed: {err}");
            return 1;
        }
    };
    let rows = backend_rows_with(&live);
    if json {
        let caps = serde_json::json!({
            "uprobe_multi": gates[0].1,
            "cookies": gates[1].1,
            "ringbuf": gates[2].1,
            "btf": gates[3].1,
        });
        let kcaps = serde_json::json!({
            "uprobe_multi": live.gates[0].1,
            "cookies": live.gates[1].1,
            "ringbuf": live.gates[2].1,
            "btf": live.gates[3].1,
        });
        let backends: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "state": row.state,
                    "note": row.note,
                    "capabilities": if row.id == "synthetic" {
                        Some(&caps)
                    } else if row.id == "kcrypto" {
                        Some(&kcaps)
                    } else {
                        None
                    },
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
        if row.id == "kcrypto" {
            let gates = live
                .gates
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(stdout, "  requires: {gates}");
        }
    }
    0
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

    #[test]
    fn failing_gates_table_pins_each_gate() {
        let all = CapabilityRequirements {
            uprobe_multi: true,
            cookies: true,
            ringbuf: true,
            btf: true,
        };
        let runtime = RuntimeCapabilities {
            kernel_release: String::from("test"),
            uprobe_multi: true,
            cookies: false,
            ringbuf: true,
            btf_present: false,
            userns: false,
            yama_scope: 0,
            caps: Vec::new(),
        };
        assert_eq!(failing_gates(&all, &runtime), ["cookies", "btf"]);
        assert!(runtime.satisfies(&CapabilityRequirements {
            uprobe_multi: true,
            ringbuf: true,
            ..CapabilityRequirements::default()
        }));
        assert!(!runtime.satisfies(&all));
        assert!(failing_gates(&CapabilityRequirements::default(), &runtime).is_empty());
    }

    #[test]
    fn live_kcrypto_row_matches_host_btf() {
        // Unprivileged: detect succeeds iff vmlinux BTF reads; the gate
        // tracks the same file, so available ⟺ BTF present.
        let live = live_kcrypto_gates().expect("gating is total");
        assert_eq!(
            live.gates,
            [
                ("uprobe_multi", false),
                ("cookies", false),
                ("ringbuf", false),
                ("btf", true),
            ]
        );
        if std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok() {
            assert_eq!(live.state, "available");
            assert!(live.note.is_none());
        } else {
            assert_eq!(live.state, "unavailable");
            let note = live.note.expect("exact error");
            assert!(note.contains("kcrypto_btf_unresolvable"), "{note}");
        }
    }
}
