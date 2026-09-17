// SPDX-License-Identifier: GPL-3.0-or-later
//! `backends`: registry states plus capability gates.
//!
//! The registry carries the synthetic backend (leaked once: the registry
//! API requires `&'static`); the other three rows are static thin-spine
//! states shared with [`crate::cmd_doctor`].

use kryprobe_core::backend::{Backend, BackendRegistry};
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

/// Synthetic capability gates from a live registry (deterministic).
fn synthetic_gates() -> [(&'static str, bool); 4] {
    let mut registry = BackendRegistry::new();
    let leaked: &'static dyn Backend = Box::leak(Box::new(SyntheticBackend::new(Vec::new())));
    // Fresh registry + unique id: registration is infallible by construction.
    registry
        .register(leaked)
        .expect("fresh registry accepts synthetic");
    let backend = registry
        .discover_all()
        .into_iter()
        .find(|b| b.capabilities().name == "synthetic")
        .expect("synthetic registered");
    let required = &backend.capabilities().required;
    [
        ("uprobe_multi", required.uprobe_multi),
        ("cookies", required.cookies),
        ("ringbuf", required.ringbuf),
        ("btf", required.btf),
    ]
}

/// Runs `backends`; always exit 0.
pub fn run(json: bool, stdout: &mut dyn Write) -> i32 {
    let rows = backend_rows();
    if json {
        let gates = synthetic_gates();
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
            let gates = synthetic_gates()
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(stdout, "  requires: {gates}");
        }
    }
    0
}
