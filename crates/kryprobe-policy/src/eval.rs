// SPDX-License-Identifier: GPL-3.0-or-later
//! Evaluation: deny/report rules over one capture into a 3-state
//! verdict (D7 — violation / clean-with-coverage / inconclusive).
//!
//! Fail-closed rule (H-SEC-02): a deny rule is evaluated only against
//! observations carrying every key it constrains; a deny rule with
//! in-source observations but none fully specified makes the capture
//! `Inconclusive` (dimension `evidence-shape`), never `Clean`. A rule
//! with no in-source observations at all is inapplicable, not
//! unevaluable.

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
    /// No deny matched but the capture cannot prove absence:
    /// coverage has gaps on rule dimensions, or a deny rule's
    /// constrained keys are absent from every in-source observation
    /// (`evidence-shape` dimension, H-SEC-02).
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
    // K5 attribution keys: `comm` is a D5 glob over the payload `comm`
    // (missing reads as `""`, like every other glob key); `uid` is an
    // exact u32 over the payload `uid` number (missing or non-numeric
    // never matches).
    if let Some(pattern) = &spec.comm
        && !glob::matches(pattern, payload_str(payload, "comm"))
    {
        return false;
    }
    if let Some(uid) = spec.uid
        && payload.get("uid").and_then(serde_json::Value::as_u64) != Some(u64::from(uid))
    {
        return false;
    }
    true
}

/// Whether a deny rule is evaluable against an observation: the
/// source must agree and every constrained evidence key must be
/// present and correctly typed in the payload.
///
/// A missing key is not a non-match — it means the evidence cannot
/// answer the rule (producer skew, shape drift, carrier rows).
/// Matching against absent keys fails open toward `Clean` for exact
/// patterns (glob vs `""` misses) and fabricates `Violation`s for
/// exclusions (`driver_not` vs `""` passes), so both directions fail
/// closed here (H-SEC-02): matches count only on fully-specified
/// observations, and a deny rule with no fully-specified in-source
/// observation makes the capture `Inconclusive` instead of `Clean`.
///
/// Out of scope by design: `stage` (row/phase gating is matching
/// semantics, D3) and `module` over kernel-crypto (explicit backend
/// gate that never matches v0.1 data, D4 — other backends must carry
/// the key).
fn rule_specified(rule: &Rule, obs: &NativeObservation) -> bool {
    if rule.source != source_name(obs.backend) {
        return false;
    }
    let spec = &rule.match_spec;
    let payload = &obs.backend_payload;
    for (pattern, key) in [
        (&spec.algorithm, "algorithm"),
        (&spec.driver, "driver"),
        (&spec.family, "family"),
        (&spec.operation, "op"),
        (&spec.result, "result"),
        (&spec.context, "context"),
        (&spec.comm, "comm"),
    ] {
        if pattern.is_some()
            && payload
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_none()
        {
            return false;
        }
    }
    // `driver_not` constrains the driver key too: without a driver to
    // exclude on, the rule cannot be evaluated.
    if spec.driver_not.is_some()
        && payload
            .get("driver")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        return false;
    }
    if spec.module.is_some()
        && obs.backend != BackendId::KCrypto
        && payload
            .get("module")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        return false;
    }
    // `uid` is an exact u32: presence + numeric type is specifiedness;
    // the value comparison itself stays in `rule_matches`.
    if spec.uid.is_some()
        && payload
            .get("uid")
            .and_then(serde_json::Value::as_u64)
            .is_none()
    {
        return false;
    }
    true
}

/// Evaluates a policy over one capture: the first matching `deny`
/// rule (policy order) is a violation; `report` matches never
/// violate; with no deny match the coverage contract decides
/// Clean (COMPLETE) vs Inconclusive (gaps on rule dimensions).
///
/// Fail-closed (H-SEC-02): matches count only on fully-specified
/// observations, and a deny rule that has in-source observations but
/// no fully-specified one makes the capture `Inconclusive` (with an
/// `evidence-shape` dimension) instead of `Clean` — absence of
/// evidence is not evidence of absence. A deny rule with no
/// in-source observations at all is inapplicable and contributes
/// nothing.
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
        let matched: Vec<&NativeObservation> = obs
            .iter()
            .filter(|obs| rule_matches(rule, obs) && rule_specified(rule, obs))
            .collect();
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
    let unevaluable = policy.rules.iter().any(|rule| {
        if rule.decision != Decision::Deny {
            return false;
        }
        // Inapplicable (no in-source observations) is not unevaluable:
        // only a rule that should have been answerable, but finds no
        // fully-specified observation, fails closed.
        let mut any_in_source = false;
        for ob in obs {
            if rule.source == source_name(ob.backend) {
                any_in_source = true;
                if rule_specified(rule, ob) {
                    return false;
                }
            }
        }
        any_in_source
    });
    if !unevaluable && coverage.overall() == CoverageStatus::CompleteForDeclaredBoundary {
        PolicyVerdict::Clean
    } else {
        let mut missing_dims: Vec<String> = coverage
            .weaker_dimensions()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if unevaluable {
            missing_dims.push("evidence-shape".to_owned());
        }
        PolicyVerdict::Inconclusive { missing_dims }
    }
}
