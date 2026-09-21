// SPDX-License-Identifier: GPL-3.0-or-later
//! Policy-verdict rendering (1B-M8): the `check` verdict mapping as a
//! shared module, not command-local code.
//!
//! Pure over the evaluated verdict + session coverage: violation names
//! the rule/counts/evidence, clean is one word, inconclusive lists the
//! kp2 §8 gap dims (same trailer vocabulary as the report PARTIAL
//! trailer).

use kryprobe_core::evidence::CoverageSummary;
use kryprobe_policy::PolicyVerdict;

/// Rendered verdict: stdout line, stderr detail, exit code.
pub struct CheckRender {
    /// Verdict line for stdout.
    pub stdout: String,
    /// Evidence detail for stderr (empty for clean).
    pub stderr: String,
    /// Process exit code (10/0/3).
    pub code: i32,
}

/// Maps an evaluated policy verdict to its rendered lines + exit code
/// (10 violation, 0 clean, 3 inconclusive).
#[must_use]
pub fn render_check_verdict(verdict: PolicyVerdict<'_>, coverage: &CoverageSummary) -> CheckRender {
    match verdict {
        PolicyVerdict::Violation {
            rule,
            obs_ids,
            algorithm,
            driver,
            context,
            evidence,
        } => {
            let stdout = format!("VIOLATION rule={rule} observations={}\n", obs_ids.len());
            let ids = obs_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let mut stderr = format!(
                "check: violation rule='{rule}' matched={} algorithm='{}' driver='{}' context='{}' evidence=obs[{ids}]\n",
                obs_ids.len(),
                kryprobe_report::live_render::show(&algorithm),
                kryprobe_report::live_render::show(&driver),
                kryprobe_report::live_render::show(&context),
            );
            // First matched observation verbatim: the lossless evidence
            // behind the summary (names/counts only — C10 holds).
            if let Some(first) = evidence.first() {
                let rendered = serde_json::to_string(first).expect("live evidence serializes");
                stderr.push_str(&format!("check: evidence: {rendered}\n"));
            }
            CheckRender {
                stdout,
                stderr,
                code: 10,
            }
        }
        PolicyVerdict::Clean => CheckRender {
            stdout: String::from("CLEAN\n"),
            stderr: String::new(),
            code: 0,
        },
        PolicyVerdict::Inconclusive { .. } => {
            // kp2 §8 tokens via the shared trailer (same dims as the
            // report PARTIAL trailer — one gap vocabulary).
            let dims = kryprobe_report::live_render::trailer_dims(coverage).join(",");
            CheckRender {
                stdout: format!("INCONCLUSIVE missing={dims}\n"),
                stderr: format!("check: inconclusive: coverage gaps on {dims}\n"),
                code: 3,
            }
        }
    }
}
