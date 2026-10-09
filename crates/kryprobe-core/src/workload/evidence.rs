// SPDX-License-Identifier: GPL-3.0-or-later
//! Association status and evidence (ADR-0008 §(g), as corrected by the
//! Stage 2A contract ADR): categorical, never percentages; metadata-file
//! content is asserted until corroborated.
//!
//! Relationships are typed (spec §3.3): hook context is the only
//! relationship M1 evidence can verify or assert — workload origin,
//! submitter, completion, and consumer claims stay unresolved or
//! unsupported until a later milestone proves them. Diagnostics are
//! static strings: they never echo untrusted input bytes (D09).

use serde::{Deserialize, Serialize};

/// Method vocabulary (frozen, Stage 2A contract): every association
/// method is one of these exact strings. Verified status is reachable
/// only through the two kernel-corroborated methods below; metadata and
/// adapter methods can never self-promote past asserted.
pub const METHOD_CAPTURED_CGROUP: &str = "captured_cgroup";
/// Unprivileged host cgroup-tree walk binding a captured kernel cgroup
/// id to a live cgroupfs object (Stage 2B resolver): kernel-corroborated
/// via inode match, verified-eligible with a validity interval.
pub const METHOD_CGROUP_INODE_BIND: &str = "cgroup_inode_bind";
/// Operator-supplied metadata-file assertion: asserted at most.
pub const METHOD_METADATA_FILE: &str = "metadata_file";
/// Metadata-label assertion: asserted at most.
pub const METHOD_METADATA_LABEL: &str = "metadata_label";
/// Runtime/Kubernetes adapter assertion (M2): asserted at most.
pub const METHOD_RUNTIME_ADAPTER: &str = "runtime_adapter";
/// No association established: the method of an unresolved association.
pub const METHOD_UNRESOLVED: &str = "unresolved";

/// The closed method vocabulary: every association method, whatever its
/// status, is one of these six exact strings (snapshot schema `$defs`
/// `evidence.method`). Schema-invalid methods refuse at decode.
const METHOD_VOCABULARY: [&str; 6] = [
    METHOD_CAPTURED_CGROUP,
    METHOD_CGROUP_INODE_BIND,
    METHOD_METADATA_FILE,
    METHOD_METADATA_LABEL,
    METHOD_RUNTIME_ADAPTER,
    METHOD_UNRESOLVED,
];

/// Categorical association status. No confidence percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionStatus {
    /// Kernel-verified association (captured id bound to a live object).
    Verified,
    /// Operator/metadata assertion, not kernel-corroborated.
    Asserted,
    /// No association established yet.
    Unresolved,
    /// More than one candidate; counts stay split, never merged.
    Ambiguous,
    /// Association outlived its validity interval.
    Stale,
    /// Association cannot be established in this environment.
    Unsupported,
}

/// The relationship an association claims (spec §3.3). Hook context is
/// observed at the instrumented boundary; every other relationship needs
/// causal evidence M1 does not produce, so M1 statuses stronger than
/// unresolved/unsupported refuse for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    /// The execution context at the instrumented boundary.
    HookContext,
    /// The context that submitted this crypto request (M3 lifecycle).
    Submitter,
    /// The context executing the observed completion boundary (M3).
    CompletionContext,
    /// The originating application/container (no M1 causal support).
    WorkloadOrigin,
    /// The kernel subsystem using crypto (M3 classification).
    Consumer,
}

/// Validity clock domain (frozen, Stage 2A contract). Exactly one value
/// exists: unknown clock domains refuse until a contract extends them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockDomain {
    /// CLOCK_MONOTONIC boot-time nanoseconds — the `start_ns` domain.
    MonotonicBoot,
}

/// A validity interval with its clock domain. Intervals are interpreted
/// within the enclosing snapshot's kernel/boot scope (exact-matched by
/// the resolver); comparing intervals across scopes is meaningless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityInterval {
    /// Interval start, inclusive (monotonic boot-time ns).
    pub start_ns: u64,
    /// Interval end, inclusive (monotonic boot-time ns).
    pub end_ns: u64,
    /// The clock this interval is measured in.
    pub clock: ClockDomain,
}

impl ValidityInterval {
    /// A monotonic-boot interval (the only domain M1 produces).
    #[must_use]
    pub fn monotonic(start_ns: u64, end_ns: u64) -> Self {
        Self {
            start_ns,
            end_ns,
            clock: ClockDomain::MonotonicBoot,
        }
    }

    /// Well-ordered (`start <= end`) intervals only.
    #[must_use]
    pub fn is_ordered(&self) -> bool {
        self.start_ns <= self.end_ns
    }

    /// Whether two same-scope intervals overlap.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start_ns <= other.end_ns && other.start_ns <= self.end_ns
    }
}

/// Workload origin: where the workload side of an association came
/// from. Distinct from the association method: the origin names the
/// evidence producer, the method names how it was joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadOrigin {
    /// Kernel capture path (event-time cgroup id).
    KernelCapture,
    /// Operator-supplied metadata file (untrusted input).
    OperatorMetadataFile,
    /// Runtime/Kubernetes adapter (M2; unresolved in M1).
    RuntimeAdapter,
    /// Host proc/cgroup tree walk.
    HostProc,
    /// Origin not established.
    Unknown,
}

/// Evidence for one context→workload association: relationship, method,
/// source, status, and validity interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionEvidence {
    /// Relationship kind (typed: only hook context is M1-provable).
    pub relationship: Relationship,
    /// Method, one of the frozen `METHOD_*` vocabulary.
    pub method: String,
    /// Workload origin (the evidence producer).
    pub source: WorkloadOrigin,
    /// Categorical status.
    pub status: AttributionStatus,
    /// Validity interval with clock domain; required for `Verified`.
    #[serde(default)]
    pub validity: Option<ValidityInterval>,
}

impl AttributionEvidence {
    /// Verified kernel-capture association: event-time cgroup id bound at
    /// the hook. Only [`Relationship::HookContext`] verifies.
    #[must_use]
    pub fn verified_kernel_capture(relationship: Relationship, validity: ValidityInterval) -> Self {
        Self::new(
            relationship,
            METHOD_CAPTURED_CGROUP,
            WorkloadOrigin::KernelCapture,
            AttributionStatus::Verified,
            Some(validity),
        )
    }

    /// Verified local binding (Stage 2B resolver): a captured kernel
    /// cgroup id matched to a live cgroupfs object by an unprivileged
    /// host tree walk. This is the ONLY verified-eligible host-side
    /// method; metadata assertions cannot use it (see [`Self::validate`]).
    #[must_use]
    pub fn verified_local_binding(relationship: Relationship, validity: ValidityInterval) -> Self {
        Self::new(
            relationship,
            METHOD_CGROUP_INODE_BIND,
            WorkloadOrigin::HostProc,
            AttributionStatus::Verified,
            Some(validity),
        )
    }

    /// Metadata-file/label assertion: asserted at most, never verified.
    /// `method` must be [`METHOD_METADATA_FILE`] or
    /// [`METHOD_METADATA_LABEL`]; anything else refuses in
    /// [`Self::validate`].
    #[must_use]
    pub fn asserted_metadata(
        relationship: Relationship,
        method: &str,
        validity: Option<ValidityInterval>,
    ) -> Self {
        Self::new(
            relationship,
            method,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Asserted,
            validity,
        )
    }

    /// Unresolved association: no method claim beyond the explicit
    /// unknown. Any relationship may stay unresolved — including
    /// [`Relationship::WorkloadOrigin`], the honest M1 origin state.
    #[must_use]
    pub fn unresolved(relationship: Relationship) -> Self {
        Self::new(
            relationship,
            METHOD_UNRESOLVED,
            WorkloadOrigin::Unknown,
            AttributionStatus::Unresolved,
            None,
        )
    }

    /// Record one association claim. Unvalidated; call [`Self::validate`].
    pub fn new(
        relationship: Relationship,
        method: &str,
        source: WorkloadOrigin,
        status: AttributionStatus,
        validity: Option<ValidityInterval>,
    ) -> Self {
        Self {
            relationship,
            method: method.to_string(),
            source,
            status,
            validity,
        }
    }

    /// Validity rules (all diagnostics static — no input echo):
    ///
    /// - Every supplied validity interval must be ordered, whatever the
    ///   status. Inverted asserted/stale intervals refuse (D08).
    /// - Every status carries a method inside the frozen six-word
    ///   vocabulary: schema-invalid methods refuse at decode (R3).
    /// - `Verified` requires [`Relationship::HookContext`], a
    ///   well-ordered validity interval, plus one of the two
    ///   kernel-corroborated (method, source) pairs —
    ///   (`captured_cgroup`, `KernelCapture`) or (`cgroup_inode_bind`,
    ///   `HostProc`). A `workload_origin` (or submitter/completion/
    ///   consumer) relationship can never verify in M1: hook context
    ///   does not establish origin (D07).
    /// - `Asserted`, `Stale`, and `Ambiguous` likewise require
    ///   `HookContext`: only hook-context associations are M1-assertable.
    /// - `Unresolved` and `Unsupported` accept any relationship.
    /// - Metadata/adapter methods cap at `Asserted`, whatever source
    ///   they claim: assertions cannot self-promote.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(validity) = &self.validity
            && !validity.is_ordered()
        {
            return Err("validity interval is inverted".to_string());
        }
        if !METHOD_VOCABULARY.contains(&self.method.as_str()) {
            return Err("association method is outside the frozen vocabulary".to_string());
        }
        let hook_only = matches!(
            self.status,
            AttributionStatus::Verified
                | AttributionStatus::Asserted
                | AttributionStatus::Stale
                | AttributionStatus::Ambiguous
        );
        if hook_only && self.relationship != Relationship::HookContext {
            return Err("only hook_context supports resolved association statuses".to_string());
        }
        match self.status {
            AttributionStatus::Verified => {
                let kernel_capture = self.method == METHOD_CAPTURED_CGROUP
                    && self.source == WorkloadOrigin::KernelCapture;
                let local_binding = self.method == METHOD_CGROUP_INODE_BIND
                    && self.source == WorkloadOrigin::HostProc;
                if !kernel_capture && !local_binding {
                    return Err(
                        "verified status requires hook_context with a kernel-corroborated method and source"
                            .to_string(),
                    );
                }
                if self.validity.is_none() {
                    return Err("verified status requires a validity interval".to_string());
                }
                Ok(())
            }
            AttributionStatus::Asserted => {
                let metadata_method =
                    self.method == METHOD_METADATA_FILE || self.method == METHOD_METADATA_LABEL;
                let adapter_method = self.method == METHOD_RUNTIME_ADAPTER;
                if metadata_method || adapter_method {
                    Ok(())
                } else {
                    Err("asserted status is for metadata/adapter hook-context sources".to_string())
                }
            }
            AttributionStatus::Unresolved
            | AttributionStatus::Ambiguous
            | AttributionStatus::Stale
            | AttributionStatus::Unsupported => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interval(start: u64, end: u64) -> ValidityInterval {
        ValidityInterval::monotonic(start, end)
    }

    #[test]
    fn verified_requires_method_source_and_interval() {
        let no_interval = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_CAPTURED_CGROUP,
            WorkloadOrigin::KernelCapture,
            AttributionStatus::Verified,
            None,
        );
        assert!(no_interval.validate().is_err());
        let inverted = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_CAPTURED_CGROUP,
            WorkloadOrigin::KernelCapture,
            AttributionStatus::Verified,
            Some(interval(200, 100)),
        );
        assert!(inverted.validate().is_err());
        let wrong_source = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_CAPTURED_CGROUP,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Verified,
            Some(interval(100, 200)),
        );
        assert!(wrong_source.validate().is_err());
    }

    #[test]
    fn metadata_assertion_cannot_claim_verified() {
        let overclaim = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Verified,
            Some(interval(100, 200)),
        );
        assert!(overclaim.validate().is_err());
        let honest = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Asserted,
            None,
        );
        assert!(honest.validate().is_ok());
    }

    #[test]
    fn verified_local_binding_is_accepted() {
        let binding = AttributionEvidence::verified_local_binding(
            Relationship::HookContext,
            interval(100, 200),
        );
        assert!(binding.validate().is_ok());
        let capture = AttributionEvidence::verified_kernel_capture(
            Relationship::HookContext,
            interval(100, 200),
        );
        assert!(capture.validate().is_ok());
        let unresolved = AttributionEvidence::unresolved(Relationship::HookContext);
        assert!(unresolved.validate().is_ok());
    }

    #[test]
    fn metadata_assertion_cannot_self_promote_by_method_or_source() {
        // Borrowing the verified-eligible method with a metadata source.
        let borrowed_method = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_CGROUP_INODE_BIND,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Verified,
            Some(interval(100, 200)),
        );
        assert!(borrowed_method.validate().is_err());
        // Borrowing the verified-eligible source with a metadata method.
        let borrowed_source = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            WorkloadOrigin::HostProc,
            AttributionStatus::Verified,
            Some(interval(100, 200)),
        );
        assert!(borrowed_source.validate().is_err());
        // Adapter assertions cap at asserted as well.
        let adapter = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_RUNTIME_ADAPTER,
            WorkloadOrigin::RuntimeAdapter,
            AttributionStatus::Verified,
            Some(interval(100, 200)),
        );
        assert!(adapter.validate().is_err());
        // Honest asserted forms validate.
        assert!(
            AttributionEvidence::asserted_metadata(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                None
            )
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn workload_origin_cannot_verify_or_assert_in_m1() {
        // Hook context does not establish origin: even the strongest
        // kernel-corroborated method/source pair cannot verify an origin
        // relationship.
        let origin_verified = AttributionEvidence::verified_kernel_capture(
            Relationship::WorkloadOrigin,
            interval(100, 200),
        );
        assert!(origin_verified.validate().is_err());
        let origin_asserted = AttributionEvidence::asserted_metadata(
            Relationship::WorkloadOrigin,
            METHOD_METADATA_FILE,
            None,
        );
        assert!(origin_asserted.validate().is_err());
        // The honest M1 origin state validates.
        let origin_unknown = AttributionEvidence::unresolved(Relationship::WorkloadOrigin);
        assert!(origin_unknown.validate().is_ok());
        // Submitter/completion/consumer are likewise M1-unprovable.
        for relationship in [
            Relationship::Submitter,
            Relationship::CompletionContext,
            Relationship::Consumer,
        ] {
            let asserted =
                AttributionEvidence::asserted_metadata(relationship, METHOD_METADATA_FILE, None);
            assert!(asserted.validate().is_err());
            let unresolved = AttributionEvidence::unresolved(relationship);
            assert!(unresolved.validate().is_ok());
        }
    }

    #[test]
    fn asserted_and_stale_intervals_must_be_ordered() {
        let inverted_asserted = AttributionEvidence::asserted_metadata(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            Some(interval(200, 100)),
        );
        assert!(inverted_asserted.validate().is_err());
        let inverted_stale = AttributionEvidence::new(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Stale,
            Some(interval(200, 100)),
        );
        assert!(inverted_stale.validate().is_err());
        // Diagnostics never echo the supplied method bytes.
        let err = inverted_asserted
            .validate()
            .expect_err("inverted must refuse");
        assert!(!err.contains(METHOD_METADATA_FILE));
    }
}
