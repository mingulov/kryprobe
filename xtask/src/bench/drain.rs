// SPDX-License-Identifier: GPL-3.0-or-later
//! Drain suite: events/s over 100k-call runs (median of 5, 1 warmup).

use super::{SuiteResult, SuiteStatus, locate_bpf_object, locate_fixture, median_of};
use kryprobe_privilege::bpfselftest::{
    BpfSelftestConfig, BpfSelftestError, BpfSelftestOutcome, run_bpf_selftest,
};
use std::time::Instant;

/// Fixture calls per measured run (2 records per call).
const CALLS: u64 = 100_000;
/// Measured runs after warmup.
const ITERS: usize = 5;

fn denied(stage: impl Into<String>) -> SuiteResult {
    SuiteResult {
        name: "drain",
        status: SuiteStatus::Denied {
            stage: stage.into(),
        },
    }
}

fn stage_of(err: &BpfSelftestError) -> String {
    match err {
        BpfSelftestError::Denied { stage, .. } => stage.clone(),
        BpfSelftestError::MissingArtifact { what, .. } => (*what).to_owned(),
        other => format!("{other}"),
    }
}

/// Runs the drain suite: 1 warmup + 5 timed full-pipeline runs.
pub(crate) fn run() -> SuiteResult {
    let (Some(object), Some(fixture)) = (locate_bpf_object(), locate_fixture()) else {
        return denied("missing-artifact");
    };
    let config = BpfSelftestConfig {
        calls: CALLS,
        object,
        fixture,
    };
    // Warmup also surfaces denials before any timing starts.
    if let Err(err) = run_bpf_selftest(&config) {
        return denied(stage_of(&err));
    }
    let mut rates: Vec<f64> = Vec::with_capacity(ITERS);
    let mut last: Option<BpfSelftestOutcome> = None;
    for _ in 0..ITERS {
        let start = Instant::now();
        match run_bpf_selftest(&config) {
            Ok(outcome) => {
                let secs = start.elapsed().as_secs_f64().max(1e-9);
                rates.push(outcome.received as f64 / secs);
                last = Some(outcome);
            }
            Err(err) => return denied(stage_of(&err)),
        }
    }
    let median = median_of(&mut rates);
    let last = last.expect("five measured runs");
    let loss = last.ring + last.dropped + last.queue_drops;
    SuiteResult {
        name: "drain",
        status: SuiteStatus::Ok {
            human: format!(
                "median={median:.1} events/s received={} exact={} loss={loss}",
                last.received,
                2 * CALLS
            ),
            json: serde_json::json!({
                "median_events_per_s": median,
                "received": last.received,
                "exact": 2 * CALLS,
                "loss": loss,
                "runs": ITERS,
            }),
        },
    }
}
