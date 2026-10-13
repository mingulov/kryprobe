// SPDX-License-Identifier: GPL-3.0-or-later
//! Scope decisions and the matched/nonmatched/unknown partition
//! (ADR-0008 §(g), spec F05): `observed = matched + nonmatched +
//! unknown_match` with checked arithmetic.

use super::{
    AttributionEvidence, AttributionStatus, ContextIdentity, MAX_STRING_FIELD_BYTES,
    WorkloadIdentity,
};
use serde::{Deserialize, Deserializer, Serialize};

/// Selector outcome for one observation: `Unknown` is neither match nor
/// non-match and never collapses into either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    /// Definitely matches the selector.
    Match,
    /// Definitely does not match.
    NonMatch,
    /// Match-ness cannot be established (unknown context or gap).
    Unknown,
}

/// A fixed observed population partitioned by one selector. The
/// invariant `observed = matched + nonmatched + unknown_match` is
/// established at construction with checked addition; overflow refuses.
/// Deserialization routes through the same checked constructor (D05):
/// an overflowing triple on the wire refuses instead of building a
/// partition whose `observed()` would wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ScopePartition {
    matched: u64,
    nonmatched: u64,
    unknown_match: u64,
}

/// Wire shape for [`ScopePartition`]: identical fields, checked on
/// conversion via [`ScopePartition::from_counts`].
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePartitionWire {
    matched: u64,
    nonmatched: u64,
    unknown_match: u64,
}

impl<'de> Deserialize<'de> for ScopePartition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ScopePartitionWire::deserialize(deserializer)?;
        Self::from_counts(wire.matched, wire.nonmatched, wire.unknown_match)
            .map_err(serde::de::Error::custom)
    }
}

impl ScopePartition {
    /// Build the partition, refusing on arithmetic overflow. For
    /// lifecycle records the population is admitted requests, not edges.
    pub fn from_counts(matched: u64, nonmatched: u64, unknown_match: u64) -> Result<Self, String> {
        matched
            .checked_add(nonmatched)
            .and_then(|base| base.checked_add(unknown_match))
            .map(|_| Self {
                matched,
                nonmatched,
                unknown_match,
            })
            .ok_or_else(|| "scope partition counts overflow u64".to_string())
    }

    /// Confirmed matches.
    #[must_use]
    pub fn matched(&self) -> u64 {
        self.matched
    }

    /// Confirmed non-matches.
    #[must_use]
    pub fn nonmatched(&self) -> u64 {
        self.nonmatched
    }

    /// Unknown matches: separately labeled, never hidden, never counted
    /// as confirmed matches.
    #[must_use]
    pub fn unknown_match(&self) -> u64 {
        self.unknown_match
    }

    /// The full observed population (cannot overflow: checked at build).
    #[must_use]
    pub fn observed(&self) -> u64 {
        self.matched + self.nonmatched + self.unknown_match
    }

    /// Decision for a resolvable observation.
    #[must_use]
    pub fn decision_for_known(&self, matches: bool) -> ScopeDecision {
        if matches {
            ScopeDecision::Match
        } else {
            ScopeDecision::NonMatch
        }
    }

    /// Decision for an unresolvable observation: always `Unknown`.
    #[must_use]
    pub fn decision_for_unknown(&self) -> ScopeDecision {
        ScopeDecision::Unknown
    }
}

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

/// Whether an association status supports definite comparison: the
/// usable statuses (verified/asserted/stale) cohere with resolved
/// identities per [`WorkloadObservation::validate`](super::WorkloadObservation::validate);
/// unresolved, ambiguous, and unsupported rows can never establish a
/// definite container match.
fn status_is_definite(status: AttributionStatus) -> bool {
    matches!(
        status,
        AttributionStatus::Verified | AttributionStatus::Asserted | AttributionStatus::Stale
    )
}

/// Shared scope decision for one captured row: `Match` only when the
/// row definitely belongs to the selection, `NonMatch` only when it
/// definitely does not, `Unknown` whenever match-ness cannot be
/// established. Unknown is neither match nor non-match and never
/// collapses into either.
///
/// Pure over caller values: no policy-rule evaluation enters core.
/// Scoped policy evaluation, report assembly, and replay decode all
/// share this classifier so a stored partition is always recomputed
/// from the same rule (SEM01).
#[must_use]
pub fn decide_workload_scope(
    selector: &WorkloadSelector,
    context: &ContextIdentity,
    identity: &WorkloadIdentity,
    evidence: &AttributionEvidence,
) -> ScopeDecision {
    match selector {
        WorkloadSelector::Cgroup(id) => {
            if context.cgroup == 0 {
                // Unreadable cgroup: cannot establish match-ness.
                ScopeDecision::Unknown
            } else if context.cgroup == *id {
                ScopeDecision::Match
            } else {
                ScopeDecision::NonMatch
            }
        }
        WorkloadSelector::Container { runtime, id } => {
            let Some(container) = identity.container.as_ref() else {
                // No container association (none, or pod-only): no
                // container key is established — unknown.
                return ScopeDecision::Unknown;
            };
            if !status_is_definite(evidence.status) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_invariant_holds() {
        let p = ScopePartition::from_counts(70, 20, 10).expect("valid");
        assert_eq!(p.observed(), 100);
    }

    #[test]
    fn zero_population_is_valid() {
        let p = ScopePartition::from_counts(0, 0, 0).expect("empty is valid");
        assert_eq!(p.observed(), 0);
    }

    #[test]
    fn deserialization_routes_through_checked_construction() {
        let ok: ScopePartition =
            serde_json::from_str(r#"{"matched":70,"nonmatched":20,"unknown_match":10}"#)
                .expect("valid triple decodes");
        assert_eq!(ok.observed(), 100);
        let overflow = format!(
            r#"{{"matched":{},"nonmatched":1,"unknown_match":0}}"#,
            u64::MAX
        );
        assert!(serde_json::from_str::<ScopePartition>(&overflow).is_err());
    }

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
    fn cgroup_decision_needs_a_readable_equal_cgroup() {
        use super::super::{ExecutionKind, Relationship};
        let selector = WorkloadSelector::cgroup(43812).expect("selector");
        let identity = WorkloadIdentity::none();
        let evidence = AttributionEvidence::unresolved(Relationship::HookContext);
        let decide = |cgroup| {
            decide_workload_scope(
                &selector,
                &ContextIdentity::new(7, cgroup, 1000, 1000, 555, ExecutionKind::Proc),
                &identity,
                &evidence,
            )
        };
        assert_eq!(decide(43812), ScopeDecision::Match);
        assert_eq!(decide(43813), ScopeDecision::NonMatch);
        assert_eq!(decide(0), ScopeDecision::Unknown);
    }

    #[test]
    fn container_decision_needs_a_definite_equal_key() {
        use super::super::{ExecutionKind, METHOD_METADATA_FILE, Relationship, ValidityInterval};
        const ID: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
        const OTHER: &str = "9c4d2f7a8b1e4a6c9d0f3b5a7c8e1d2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b1c3d";
        let selector = WorkloadSelector::container("docker://host-a", ID, None).expect("selector");
        let context = ContextIdentity::new(7, 43812, 1000, 1000, 555, ExecutionKind::Proc);
        let asserted = AttributionEvidence::asserted_metadata(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            Some(ValidityInterval::monotonic(100, 200)),
        );
        let decide = |identity: &WorkloadIdentity, evidence: &AttributionEvidence| {
            decide_workload_scope(&selector, &context, identity, evidence)
        };
        // Exact key matches, and observed lifetimes never narrow it.
        assert_eq!(
            decide(
                &WorkloadIdentity::container("docker://host-a", ID, Some("lifetime-a")),
                &asserted
            ),
            ScopeDecision::Match
        );
        assert_eq!(
            decide(
                &WorkloadIdentity::container("docker://host-a", ID, Some("lifetime-b")),
                &asserted
            ),
            ScopeDecision::Match
        );
        // A different key is a definite non-match.
        assert_eq!(
            decide(
                &WorkloadIdentity::container("docker://host-a", OTHER, Some("lifetime-b")),
                &asserted
            ),
            ScopeDecision::NonMatch
        );
        // No key, an indefinite status, or empty components: unknown.
        assert_eq!(
            decide(
                &WorkloadIdentity::none(),
                &AttributionEvidence::unresolved(Relationship::HookContext)
            ),
            ScopeDecision::Unknown
        );
        assert_eq!(
            decide(
                &WorkloadIdentity::container("docker://host-a", ID, Some("lifetime-a")),
                &AttributionEvidence::unresolved(Relationship::HookContext)
            ),
            ScopeDecision::Unknown
        );
        assert_eq!(
            decide(&WorkloadIdentity::container("", "", None), &asserted),
            ScopeDecision::Unknown
        );
    }

    #[test]
    fn selector_constructors_refuse_without_input_echo() {
        assert_eq!(
            WorkloadSelector::cgroup(0)
                .expect_err("cgroup 0 refuses")
                .exit_intent(),
            2
        );
        let id = "70f16eb35cd4";
        let err = WorkloadSelector::container("docker://host-a", id, None)
            .expect_err("abbreviation refuses");
        assert_eq!(err.exit_intent(), 2);
        assert!(
            !err.to_string().contains(id),
            "refusal withholds input bytes: {err}"
        );
        assert_eq!(WorkloadSelector::unsupported_kind("pod").exit_intent(), 2);
    }
}
