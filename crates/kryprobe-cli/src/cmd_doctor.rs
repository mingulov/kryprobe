// SPDX-License-Identifier: GPL-3.0-or-later
//! `doctor`: the 14-row probe matrix plus backend rows.

use crate::cmd_backends::{backend_rows, human_row};
use kryprobe_privilege::{ProbeOutcome, run_probe_matrix};
use std::io::Write;

fn human_outcome(outcome: &ProbeOutcome) -> String {
    match outcome {
        ProbeOutcome::Pass { detail } => format!("pass: {detail}"),
        ProbeOutcome::Denied { stage, errno } => format!("denied: {stage} (errno {errno})"),
        ProbeOutcome::Skipped { reason } => format!("skipped: {reason}"),
    }
}

fn json_outcome(outcome: &ProbeOutcome) -> serde_json::Value {
    match outcome {
        ProbeOutcome::Pass { detail } => serde_json::json!({"outcome": "pass", "detail": detail}),
        ProbeOutcome::Denied { stage, errno } => {
            serde_json::json!({"outcome": "denied", "stage": stage, "errno": errno})
        }
        ProbeOutcome::Skipped { reason } => {
            serde_json::json!({"outcome": "skipped", "reason": reason})
        }
    }
}

/// Runs `doctor`; always exit 0 (degraded rows are data, not failure).
pub fn run(json: bool, stdout: &mut dyn Write) -> i32 {
    let matrix = run_probe_matrix();
    if json {
        let probes: Vec<serde_json::Value> = matrix
            .rows
            .iter()
            .map(|row| {
                let mut value = json_outcome(&row.outcome);
                value["name"] = serde_json::Value::String(row.name.to_owned());
                value
            })
            .collect();
        let backends: Vec<serde_json::Value> = backend_rows()
            .iter()
            .map(|row| serde_json::json!({"id": row.id, "state": row.state, "note": row.note}))
            .collect();
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::json!({"probes": probes, "backends": backends})
        );
        return 0;
    }
    for row in &matrix.rows {
        let _ = writeln!(
            stdout,
            "probe {}: {}",
            row.name,
            human_outcome(&row.outcome)
        );
    }
    for row in &backend_rows() {
        let _ = writeln!(stdout, "backend {}", human_row(row));
    }
    0
}
