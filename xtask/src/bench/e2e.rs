// SPDX-License-Identifier: GPL-3.0-or-later
//! E2e suite: canonical synthetic script wall time (20 iterations).

use super::{SuiteResult, SuiteStatus, median_of};
use kryprobe_core::ids::{IdIssuer, SessionId};
use kryprobe_core::synthetic::{SyntheticBackend, canonical_script};
use std::time::Instant;

/// Measured script runs.
const ITERS: usize = 20;

/// Runs the e2e suite: 20 scripted sessions, median wall time.
pub(crate) fn run() -> SuiteResult {
    let backend = SyntheticBackend::new(canonical_script());
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let start = Instant::now();
        // Fresh issuer per sample: each run mints `observation:1..`
        // (1B-L1), so samples stay mutually comparable.
        if backend
            .run_script(SessionId::new(1), &IdIssuer::default())
            .is_err()
        {
            return SuiteResult {
                name: "e2e",
                status: SuiteStatus::Denied {
                    stage: "backend-error".to_owned(),
                },
            };
        }
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let median = median_of(&mut samples);
    SuiteResult {
        name: "e2e",
        status: SuiteStatus::Ok {
            human: format!("median={median:.3}ms over {ITERS} iters"),
            json: serde_json::json!({"median_ms": median, "iters": ITERS}),
        },
    }
}
