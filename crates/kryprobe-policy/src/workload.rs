// SPDX-License-Identifier: GPL-3.0-or-later
//! Workload-scoped policy (M1 Stage 2D): exact-cgroup and
//! full-container-identity selectors over typed observed rows, exact
//! weighted-call partitions, and the frozen unknown-handling truth
//! table (spec §5.5/§5.6, ADR-0012).
//!
//! Rule evaluation reuses the existing deny/report matcher
//! ([`crate::eval`] via `rule_matches`/`rule_specified`, including
//! the H-SEC-02 fail-closed specifiedness rule); only the row scope
//! is new. Selectors are post-ingestion views over the common typed
//! report projection — never confinement, never inferred ownership:
//! no descendants, no pod ownership, no abbreviated ids. Unknown
//! attribution is a separately labeled population, never a match and
//! never a lost-event count.

use kryprobe_core::evidence::NativeObservation;
use kryprobe_core::evidence::payload_keys as K;
use kryprobe_core::ids::ObservationId;
use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, ContextIdentity, MAX_STRING_FIELD_BYTES, ScopeDecision,
    ScopePartition, WorkloadIdentity, WorkloadObservation,
};

use crate::eval::{rule_matches, rule_specified};
use crate::rule::{Decision, Policy};

/// Full container id shape (frozen): 64 lowercase hex chars — the
/// same shape [`ContextIdentity::qualified_container_candidate`]
/// admits and the v2 report schema enforces.
const CONTAINER_ID_HEX_CHARS: usize = 64;

/// A workload selector: the M1 post-ingestion view kinds. Pod,
/// runtime, subtree, name, and path selectors do not exist in M1 and
/// refuse via [`WorkloadSelector::unsupported_kind`] (exit 2 at
/// integration), never silently degrading to another scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadSelector {
    /// Exact cgroup id: matches only rows captured in this cgroup.
    /// Descendants never join; `0` refuses at construction (the
    /// unreadable marker is not selectable).
    Cgroup(u64),
    /// Full container identity: runtime instance + full id ONLY. M1
    /// selectors carry no lifetime (D10: the amended v2 report wire
    /// `selectors.container` allows runtime+id only), so the selector
    /// always matches the container across lifetimes (frozen by the
    /// `matching-violation` fixture: the lifetime-less selector
    /// matches the lifetime-a row). Lifetime narrowing is not
    /// representable in M1 and refuses at construction — never
    /// silently dropped (dropping would change scope).
    Container {
        /// Runtime instance identity (non-empty, bounded).
        runtime: String,
        /// Full container id (64 lowercase hex; abbreviations refuse).
        id: String,
    },
}

/// Selector refusal: invalid or unsupported selection (exit 2 at
/// integration). Messages are static (D09): they name the rule, never
/// echo input bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorError {
    message: String,
}

impl SelectorError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }

    /// Exit intent for every selector refusal: invalid input (2).
    #[must_use]
    pub fn exit_intent(&self) -> i32 {
        2
    }
}

impl std::fmt::Display for SelectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SelectorError {}

impl WorkloadSelector {
    /// Exact-cgroup selector. Refuses `0`: the unreadable marker is
    /// not a selectable cgroup (frozen zero convention).
    pub fn cgroup(id: u64) -> Result<Self, SelectorError> {
        if id == 0 {
            return Err(SelectorError::new(
                "cgroup selector refuses id 0 (unreadable marker, never selectable)",
            ));
        }
        Ok(Self::Cgroup(id))
    }

    /// Full-container-identity selector: non-empty bounded runtime
    /// and a full 64-char lowercase-hex id (abbreviated, non-hex, or
    /// uppercase ids refuse). The `lifetime` argument must be `None`:
    /// any present lifetime refuses, because lifetime narrowing is not
    /// representable on the amended M1 report wire (D10:
    /// `selectors.container` carries runtime+id only) and silently
    /// dropping it would change scope.
    pub fn container(
        runtime: &str,
        id: &str,
        lifetime: Option<&str>,
    ) -> Result<Self, SelectorError> {
        if runtime.is_empty() || runtime.len() > MAX_STRING_FIELD_BYTES {
            return Err(SelectorError::new(
                "container selector requires a non-empty runtime within 256 bytes",
            ));
        }
        if !is_full_container_id(id) {
            return Err(SelectorError::new(
                "container selector requires a full 64-character lowercase-hex id (abbreviations refuse)",
            ));
        }
        if lifetime.is_some() {
            return Err(SelectorError::new(
                "container selector refuses a lifetime (M1 selectors are runtime + id only)",
            ));
        }
        Ok(Self::Container {
            runtime: runtime.to_string(),
            id: id.to_string(),
        })
    }

    /// Explicit refusal for selector kinds M1 does not support (pod,
    /// runtime, subtree, name, path). The kind names the caller's
    /// request; the message stays static and names the supported set.
    #[must_use]
    pub fn unsupported_kind(kind: &str) -> SelectorError {
        let _ = kind;
        SelectorError::new(
            "unsupported selector kind (M1 supports cgroup-id and container-id only)",
        )
    }
}

/// Full-id shape check: exactly 64 lowercase hex chars.
fn is_full_container_id(id: &str) -> bool {
    id.len() == CONTAINER_ID_HEX_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// One weighted observed row: the policy-crate projection of a common
/// typed report row. `calls` is the weighted-call weight aggregated
/// into this row; `context`/`identity`/`evidence` carry the frozen
/// workload association; `observation` carries the native
/// algorithm/driver/family/op/result/context/comm/uid payload the
/// existing rule evaluator reads. PID/UID/comm meanings are the
/// existing payload meanings, preserved unchanged — selection never
/// reinterprets them.
#[derive(Debug, Clone)]
pub struct ScopedRow<'a> {
    /// Observed calls aggregated into this row (partition weight).
    pub calls: u64,
    /// The captured kernel/session context.
    pub context: ContextIdentity,
    /// The workload identity established for it (possibly none).
    pub identity: WorkloadIdentity,
    /// The evidence for the association.
    pub evidence: AttributionEvidence,
    /// Native observation for the rule evaluator (borrowed: the
    /// caller owns the capture, mirroring [`crate::eval`]).
    pub observation: &'a NativeObservation,
}

impl ScopedRow<'_> {
    /// Row validity reuses the frozen observation rules
    /// ([`WorkloadObservation::validate`]): evidence validates,
    /// identity fits the string budget and is cluster-consistent, and
    /// usable statuses cohere with resolved identities. A
    /// self-contradictory row is invalid input (exit 2), never a
    /// silent non-match.
    fn validate(&self) -> Result<(), ScopedError> {
        WorkloadObservation {
            context: self.context,
            identity: self.identity.clone(),
            evidence: self.evidence.clone(),
        }
        .validate()
        .map_err(|_| {
            ScopedError::InvalidInput(
                "scoped row contradicts workload observation rules".to_string(),
            )
        })
    }
}

/// Global capture integrity for a scoped check: kept SEPARATE from
/// the scoped partition. Ledger unknown (unattributed observed calls)
/// and lost events are never scoped weights — unknown attribution is
/// not permission to invent counts.
///
/// Integration mapping (v2 report): quiescent ledger + complete
/// capture → [`CaptureIntegrity::Complete`]; unproven ledger
/// (`gap_unreconciled`) or partial capture → [`CaptureIntegrity::Partial`];
/// unavailable capture → [`CaptureIntegrity::Unusable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureIntegrity {
    /// Complete observed population: no gaps could hide
    /// selected-workload calls.
    Complete,
    /// Usable capture with gaps that could hide selected-workload
    /// calls: clean is unreachable, violations still stand.
    Partial,
    /// Capture capability unusable: no scoped conclusion possible
    /// (exit 4); evaluation does not run.
    Unusable,
}

/// Row-scope outcome: the per-row decision plus the checked weighted
/// partition (`observed = matched + nonmatched + unknown_match`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeOutcome {
    /// One decision per input row, in input order.
    pub decisions: Vec<ScopeDecision>,
    /// Checked weighted partition over `calls`.
    pub partition: ScopePartition,
}

/// Scoped evaluation failure with its exit intent (spec §5.6):
/// invalid input/schema → 2, unusable capture → 4, internal → 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedError {
    /// Invalid selector or self-contradictory row (exit 2).
    InvalidInput(String),
    /// Capture capability unusable (exit 4).
    UnusableCapture,
    /// Internal failure, e.g. unrepresentable partition sums (exit 1).
    Internal(String),
}

impl ScopedError {
    /// Exit intent for integration (`check` exit codes).
    #[must_use]
    pub fn exit_intent(&self) -> i32 {
        match self {
            ScopedError::InvalidInput(_) => 2,
            ScopedError::UnusableCapture => 4,
            ScopedError::Internal(_) => 1,
        }
    }
}

impl std::fmt::Display for ScopedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopedError::InvalidInput(detail) => write!(f, "invalid scoped input: {detail}"),
            ScopedError::UnusableCapture => write!(f, "unusable capture for scoped check"),
            ScopedError::Internal(detail) => write!(f, "internal scoped failure: {detail}"),
        }
    }
}

impl std::error::Error for ScopedError {}

impl From<SelectorError> for ScopedError {
    fn from(err: SelectorError) -> Self {
        ScopedError::InvalidInput(err.to_string())
    }
}

/// Scoped policy verdict with its exit intent (spec §5.6): a
/// definitely matching violation → 10; no matching violation plus
/// possibly matching unknown/gap → 3; a complete matching population
/// satisfying the policy → 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedVerdict<'a> {
    /// A `deny` rule matched a definitely matching row: the finding
    /// stands even with unrelated gaps (spec §5.6 — a proven matching
    /// violation remains a violation).
    Violation {
        /// Id of the first matching deny rule (policy order).
        rule: String,
        /// Matched observations in row order.
        obs_ids: Vec<ObservationId>,
        /// Representative algorithm/driver/context from the first
        /// matched observation (raw payload spellings, as system-wide).
        algorithm: String,
        /// Representative driver (see `algorithm`).
        driver: String,
        /// Representative context (see `algorithm`).
        context: String,
        /// The matched observations themselves (borrowed).
        evidence: Vec<&'a NativeObservation>,
        /// The exact scoped partition behind the verdict.
        partition: ScopePartition,
    },
    /// No deny matched and the matching population is complete:
    /// every observed call is definitely classified, capture has no
    /// gaps, and every in-scope deny rule was evaluable.
    Clean {
        /// The exact scoped partition behind the verdict.
        partition: ScopePartition,
    },
    /// No deny matched but the selected conclusion is unproven:
    /// unknown weight that could belong to the workload, capture
    /// gaps that could hide its calls, or an in-scope deny rule no
    /// fully-specified matching row could answer.
    Inconclusive {
        /// Weaker dimensions in fixed order
        /// (`capture-gap`, `unknown-match`, `evidence-shape`).
        missing: Vec<String>,
        /// The exact scoped partition behind the verdict.
        partition: ScopePartition,
    },
}

impl ScopedVerdict<'_> {
    /// Exit intent for integration: 10 violation, 0 clean,
    /// 3 inconclusive.
    #[must_use]
    pub fn exit_intent(&self) -> i32 {
        match self {
            ScopedVerdict::Violation { .. } => 10,
            ScopedVerdict::Clean { .. } => 0,
            ScopedVerdict::Inconclusive { .. } => 3,
        }
    }

    /// The exact scoped partition behind any verdict.
    #[must_use]
    pub fn partition(&self) -> ScopePartition {
        match self {
            ScopedVerdict::Violation { partition, .. }
            | ScopedVerdict::Clean { partition }
            | ScopedVerdict::Inconclusive { partition, .. } => *partition,
        }
    }
}

/// Raw payload string (empty when missing — a glob that must not
/// match simply won't), mirroring [`crate::eval`].
fn payload_str<'a>(payload: &'a serde_json::Value, key: &str) -> &'a str {
    kryprobe_core::evidence::payload_str_opt(payload, key).unwrap_or("")
}

/// Whether an association status supports definite comparison: the
/// usable statuses (verified/asserted/stale) cohere with resolved
/// identities per [`WorkloadObservation::validate`]; unresolved,
/// ambiguous, and unsupported rows can never establish a definite
/// container match.
fn status_is_definite(status: AttributionStatus) -> bool {
    matches!(
        status,
        AttributionStatus::Verified | AttributionStatus::Asserted | AttributionStatus::Stale
    )
}

/// Scope decision for one row: `Match` only when the row definitely
/// belongs to the selection, `NonMatch` only when it definitely does
/// not, `Unknown` whenever match-ness cannot be established. Unknown
/// is neither match nor non-match and never collapses into either.
fn decide(selector: &WorkloadSelector, row: &ScopedRow<'_>) -> ScopeDecision {
    match selector {
        WorkloadSelector::Cgroup(id) => {
            if row.context.cgroup == 0 {
                // Unreadable cgroup: cannot establish match-ness.
                ScopeDecision::Unknown
            } else if row.context.cgroup == *id {
                ScopeDecision::Match
            } else {
                ScopeDecision::NonMatch
            }
        }
        WorkloadSelector::Container { runtime, id } => {
            let Some(container) = row.identity.container.as_ref() else {
                // No container association (none, or pod-only): no
                // container key is established — unknown.
                return ScopeDecision::Unknown;
            };
            if !status_is_definite(row.evidence.status) {
                return ScopeDecision::Unknown;
            }
            if container.runtime.is_empty() || container.id.is_empty() {
                // Empty components establish no key (frozen
                // `identity_keys` rule) — unknown.
                return ScopeDecision::Unknown;
            }
            if container.runtime != *runtime || container.id != *id {
                return ScopeDecision::NonMatch;
            }
            // Runtime+id equality is the whole M1 match: observed row
            // lifetimes never narrow the selection (D10 — the selector
            // wire carries runtime+id only, so matching spans
            // lifetimes by construction).
            ScopeDecision::Match
        }
    }
}

/// Partitions weighted rows under one selector: validates every row
/// (invalid → [`ScopedError::InvalidInput`], exit 2), decides each
/// row exactly once (no double count), and sums `calls` into the
/// checked [`ScopePartition`] (`observed = matched + nonmatched +
/// unknown_match`; unrepresentable sums → [`ScopedError::Internal`],
/// exit 1).
pub fn scope_rows(
    selector: &WorkloadSelector,
    rows: &[ScopedRow<'_>],
) -> Result<ScopeOutcome, ScopedError> {
    let mut decisions = Vec::with_capacity(rows.len());
    let (mut matched, mut nonmatched, mut unknown_match) = (0u64, 0u64, 0u64);
    for row in rows {
        row.validate()?;
        let decision = decide(selector, row);
        let bucket = match decision {
            ScopeDecision::Match => &mut matched,
            ScopeDecision::NonMatch => &mut nonmatched,
            ScopeDecision::Unknown => &mut unknown_match,
        };
        *bucket = bucket.checked_add(row.calls).ok_or_else(|| {
            ScopedError::Internal("scoped partition counts overflow u64".to_string())
        })?;
        decisions.push(decision);
    }
    let partition = ScopePartition::from_counts(matched, nonmatched, unknown_match)
        .map_err(ScopedError::Internal)?;
    Ok(ScopeOutcome {
        decisions,
        partition,
    })
}

/// Evaluates a policy over the definitely matching rows: the first
/// matching `deny` rule (policy order) over definitely matching,
/// fully-specified rows is a violation; `report` matches never
/// violate. Rows outside the definite match (nonmatched or unknown)
/// are never evaluated for violations: an algorithm seen only in
/// unknown scope cannot convict the selected workload.
///
/// Fail-closed (H-SEC-02, scoped): matches count only on
/// fully-specified rows, and a deny rule with in-scope in-source rows
/// but no fully-specified one makes the check `Inconclusive`
/// (`evidence-shape`) instead of `Clean`. A deny rule with no
/// in-scope in-source rows at all is inapplicable, not unevaluable.
///
/// Order mirrors `check`: invalid input refuses (2) before capture
/// state is consulted; unusable capture refuses (4) before any
/// evaluation; then 10/3/0.
pub fn evaluate_scoped<'a>(
    policy: &Policy,
    selector: &WorkloadSelector,
    rows: &[ScopedRow<'a>],
    integrity: CaptureIntegrity,
) -> Result<ScopedVerdict<'a>, ScopedError> {
    let scoped = scope_rows(selector, rows)?;
    if integrity == CaptureIntegrity::Unusable {
        return Err(ScopedError::UnusableCapture);
    }
    let matched_obs: Vec<&'a NativeObservation> = scoped
        .decisions
        .iter()
        .zip(rows.iter())
        .filter(|(decision, _)| **decision == ScopeDecision::Match)
        .map(|(_, row)| row.observation)
        .collect();

    for rule in &policy.rules {
        if rule.decision != Decision::Deny {
            continue;
        }
        let matched: Vec<&NativeObservation> = matched_obs
            .iter()
            .copied()
            .filter(|obs| rule_matches(rule, obs) && rule_specified(rule, obs))
            .collect();
        if matched.is_empty() {
            continue;
        }
        let first = matched[0];
        return Ok(ScopedVerdict::Violation {
            rule: rule.id.clone(),
            obs_ids: matched.iter().map(|obs| obs.id).collect(),
            algorithm: payload_str(&first.backend_payload, K::ALGORITHM).to_owned(),
            driver: payload_str(&first.backend_payload, K::DRIVER).to_owned(),
            context: payload_str(&first.backend_payload, K::CONTEXT).to_owned(),
            evidence: matched,
            partition: scoped.partition,
        });
    }

    let unevaluable = policy.rules.iter().any(|rule| {
        if rule.decision != Decision::Deny {
            return false;
        }
        let mut any_specified = false;
        for obs in &matched_obs {
            if rule_specified(rule, obs) {
                any_specified = true;
                break;
            }
        }
        // Inapplicable (no in-scope in-source rows) is not
        // unevaluable: only a rule that should have been answerable,
        // but finds no fully-specified row, fails closed. Note
        // `rule_specified` already gates on source agreement, so
        // foreign-source rows contribute neither matches nor
        // specifiedness.
        let any_in_source = matched_obs.iter().any(|obs| rule_in_source(rule, obs));
        any_in_source && !any_specified
    });

    let mut missing = Vec::new();
    if integrity == CaptureIntegrity::Partial {
        missing.push("capture-gap".to_string());
    }
    if scoped.partition.unknown_match() > 0 {
        missing.push("unknown-match".to_string());
    }
    if unevaluable {
        missing.push("evidence-shape".to_string());
    }
    if missing.is_empty() {
        Ok(ScopedVerdict::Clean {
            partition: scoped.partition,
        })
    } else {
        Ok(ScopedVerdict::Inconclusive {
            missing,
            partition: scoped.partition,
        })
    }
}

/// Whether a rule's source agrees with an observation's backend:
/// the same source gate `rule_specified` applies internally.
fn rule_in_source(rule: &crate::rule::Rule, obs: &NativeObservation) -> bool {
    rule.source == crate::eval::source_name(obs.backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_id_shape_is_exact() {
        assert!(is_full_container_id(
            "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57"
        ));
        assert!(!is_full_container_id("70f16eb35cd4"));
        assert!(!is_full_container_id(&"g".repeat(64)));
        assert!(!is_full_container_id(
            "70F16EB35CD4991D07A1545BEB8522E7F3F59B6642AA2F2AFECFF68F2BE2EB57"
        ));
        assert!(!is_full_container_id(""));
    }

    #[test]
    fn present_lifetime_refuses_without_input_echo() {
        // D10: the amended report wire carries runtime+id only, so any
        // present selector lifetime — empty, bounded, or oversize —
        // refuses explicitly (exit 2) rather than narrowing or
        // silently dropping (dropping would change scope).
        let id = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
        let big = "l".repeat(MAX_STRING_FIELD_BYTES + 1);
        for lifetime in [Some("lifetime-a"), Some(""), Some(big.as_str())] {
            let err = WorkloadSelector::container("docker://host-a", id, lifetime)
                .expect_err("present lifetime refuses");
            assert_eq!(err.exit_intent(), 2);
            assert!(
                !err.to_string().contains("lifetime-a"),
                "refusal withholds input bytes: {err}"
            );
        }
    }

    #[test]
    fn selector_refusals_are_exit_2_without_input_echo() {
        let id = "70f16eb35cd4";
        let err = WorkloadSelector::container("docker://host-a", id, None)
            .expect_err("abbreviation refuses");
        assert_eq!(err.exit_intent(), 2);
        assert!(
            !err.to_string().contains(id),
            "refusal withholds input bytes: {err}"
        );
    }

    #[test]
    fn error_exit_intents_match_spec_family() {
        assert_eq!(
            ScopedError::InvalidInput("static".to_string()).exit_intent(),
            2
        );
        assert_eq!(ScopedError::UnusableCapture.exit_intent(), 4);
        assert_eq!(ScopedError::Internal("static".to_string()).exit_intent(), 1);
        let partition = ScopePartition::from_counts(1, 0, 0).expect("valid");
        assert_eq!(ScopedVerdict::Clean { partition }.exit_intent(), 0);
        assert_eq!(
            ScopedVerdict::Inconclusive {
                missing: vec!["unknown-match".to_string()],
                partition,
            }
            .exit_intent(),
            3
        );
    }
}
