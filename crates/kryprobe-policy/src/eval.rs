// SPDX-License-Identifier: GPL-3.0-or-later
//! Evaluation: deny/report rules over one capture into a 3-state
//! verdict (D7 — violation / clean-with-coverage / inconclusive).

use crate::glob;
use crate::rule::{Decision, Policy, Rule, Stage};
use kryprobe_core::enums::{BackendId, CoverageStatus, EvidencePhase};
use kryprobe_core::evidence::{CoverageSummary, NativeObservation};
use kryprobe_core::ids::ObservationId;

/// 3-state policy verdict (kp2 §8/`check`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// A `deny` rule matched: the finding stands even when other
    /// coverage is partial (kp2 §8 — a real observation is evidence).
    Violation {
        /// Id of the first matching deny rule (policy order).
        rule: String,
        /// Matched observations in capture order.
        obs_ids: Vec<ObservationId>,
        /// Representative algorithm/driver/context from the first
        /// matched observation (raw payload spellings).
        algorithm: String,
        /// Representative driver (see [`PolicyVerdict::Violation::algorithm`]).
        driver: String,
        /// Representative context (see [`PolicyVerdict::Violation::algorithm`]).
        context: String,
        /// The matched observations themselves (full evidence).
        evidence: Vec<NativeObservation>,
    },
    /// No deny matched and rule-dimension coverage is COMPLETE.
    Clean,
    /// No deny matched but coverage has gaps on rule dimensions:
    /// absence of a finding is not evidence of absence.
    Inconclusive {
        /// Weaker coverage dimensions in core order.
        missing_dims: Vec<String>,
    },
}

/// Capture-source name for a backend (`kernel-crypto` is the v0.1
/// live source; `p11`/`openssl` arrive with their backends).
fn source_name(backend: BackendId) -> &'static str {
    match backend {
        BackendId::KCrypto => "kernel-crypto",
        BackendId::P11 => "p11",
        BackendId::OpenSsl => "openssl",
        BackendId::Synthetic => "synthetic",
    }
}

/// Raw payload string (empty when missing or not a string — a glob
/// that must not match simply won't).
fn payload_str<'a>(payload: &'a serde_json::Value, key: &str) -> &'a str {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// Stage match (D3): only agg rows carry a stage — totals/ident rows
/// are carriers/markers and never match (even though totals carry
/// `Completed`).
fn stage_matches(stage: Stage, obs: &NativeObservation) -> bool {
    if payload_str(&obs.backend_payload, "row") != "agg" {
        return false;
    }
    match stage {
        Stage::Selected => obs.phase == EvidencePhase::Selected,
        Stage::Executed => matches!(
            obs.phase,
            EvidencePhase::Entered | EvidencePhase::Returned | EvidencePhase::Completed
        ),
    }
}

/// Module match (D4): never matches kernel-crypto v0.1 observations
/// (module is not captured — explicit backend gate, not key absence);
/// import-shaped observations match their payload module by glob.
fn module_matches(pattern: &str, obs: &NativeObservation) -> bool {
    if obs.backend == BackendId::KCrypto {
        return false;
    }
    glob::matches(pattern, payload_str(&obs.backend_payload, "module"))
}

/// A rule matches an observation only if the source agrees and ALL
/// present keys match.
fn rule_matches(rule: &Rule, obs: &NativeObservation) -> bool {
    if rule.source != source_name(obs.backend) {
        return false;
    }
    let spec = &rule.match_spec;
    let payload = &obs.backend_payload;
    if let Some(stage) = spec.stage
        && !stage_matches(stage, obs)
    {
        return false;
    }
    // (`operation` reads the payload `op` spelling.)
    for (pattern, key) in [
        (&spec.algorithm, "algorithm"),
        (&spec.driver, "driver"),
        (&spec.family, "family"),
        (&spec.operation, "op"),
        (&spec.result, "result"),
        (&spec.context, "context"),
    ] {
        if let Some(pattern) = pattern
            && !glob::matches(pattern, payload_str(payload, key))
        {
            return false;
        }
    }
    if let Some(pattern) = &spec.driver_not
        && glob::matches(pattern, payload_str(payload, "driver"))
    {
        return false;
    }
    if let Some(pattern) = &spec.module
        && !module_matches(pattern, obs)
    {
        return false;
    }
    true
}

/// Evaluates a policy over one capture: the first matching `deny`
/// rule (policy order) is a violation; `report` matches never
/// violate; with no deny match the coverage contract decides
/// Clean (COMPLETE) vs Inconclusive (gaps on rule dimensions).
#[must_use]
pub fn evaluate(
    policy: &Policy,
    obs: &[NativeObservation],
    coverage: &CoverageSummary,
) -> PolicyVerdict {
    for rule in &policy.rules {
        if rule.decision != Decision::Deny {
            continue;
        }
        let matched: Vec<&NativeObservation> =
            obs.iter().filter(|obs| rule_matches(rule, obs)).collect();
        if matched.is_empty() {
            continue;
        }
        let first = matched[0];
        return PolicyVerdict::Violation {
            rule: rule.id.clone(),
            obs_ids: matched.iter().map(|obs| obs.id).collect(),
            algorithm: payload_str(&first.backend_payload, "algorithm").to_owned(),
            driver: payload_str(&first.backend_payload, "driver").to_owned(),
            context: payload_str(&first.backend_payload, "context").to_owned(),
            evidence: matched.into_iter().cloned().collect(),
        };
    }
    if coverage.overall() == CoverageStatus::CompleteForDeclaredBoundary {
        PolicyVerdict::Clean
    } else {
        PolicyVerdict::Inconclusive {
            missing_dims: coverage
                .weaker_dimensions()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
}
