// SPDX-License-Identifier: GPL-3.0-or-later
//! Association status and evidence (ADR-0008 §(g)): categorical, never
//! percentages; metadata-file content is asserted until corroborated.

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
pub struct AttributionEvidence {
    /// Relationship kind, e.g. `hook_context`.
    pub relationship: String,
    /// Method, e.g. `captured_cgroup`, `metadata_file`, `metadata_label`.
    pub method: String,
    /// Workload origin (the evidence producer).
    pub source: WorkloadOrigin,
    /// Categorical status.
    pub status: AttributionStatus,
    /// Validity interval `[start_ns, end_ns]`; required for `Verified`.
    pub validity: Option<(u64, u64)>,
}

impl AttributionEvidence {
    /// Verified kernel-capture association: event-time cgroup id bound at
    /// the hook. Validity is a monotonic boot-time-nanosecond interval
    /// (the same clock domain as `start_ns`), never wall clock.
    #[must_use]
    pub fn verified_kernel_capture(relationship: &str, validity: (u64, u64)) -> Self {
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
    pub fn verified_local_binding(relationship: &str, validity: (u64, u64)) -> Self {
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
        relationship: &str,
        method: &str,
        validity: Option<(u64, u64)>,
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
    /// unknown.
    #[must_use]
    pub fn unresolved(relationship: &str) -> Self {
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
        relationship: &str,
        method: &str,
        source: WorkloadOrigin,
        status: AttributionStatus,
        validity: Option<(u64, u64)>,
    ) -> Self {
        Self {
            relationship: relationship.to_string(),
            method: method.to_string(),
            source,
            status,
            validity,
        }
    }

    /// Validity rules: `Verified` requires a well-ordered validity
    /// interval plus one of the two kernel-corroborated
    /// (method, source) pairs — (`captured_cgroup`, `KernelCapture`)
    /// or (`cgroup_inode_bind`, `HostProc`); anything else claiming
    /// `Verified` is a contradiction and refuses. Metadata-file content
    /// stronger than `Asserted` without corroboration refuses, whatever
    /// source it claims. All validity intervals are monotonic boot-time
    /// nanoseconds (the `start_ns` clock domain), never wall clock.
    pub fn validate(&self) -> Result<(), String> {
        if self.relationship.is_empty() || self.method.is_empty() {
            return Err("relationship and method must be non-empty".to_string());
        }
        match self.status {
            AttributionStatus::Verified => {
                let kernel_capture = self.method == METHOD_CAPTURED_CGROUP
                    && self.source == WorkloadOrigin::KernelCapture;
                let local_binding = self.method == METHOD_CGROUP_INODE_BIND
                    && self.source == WorkloadOrigin::HostProc;
                if !kernel_capture && !local_binding {
                    return Err(format!(
                        "verified status requires a kernel-corroborated (method, source) pair, got '{}' + '{:?}'",
                        self.method, self.source
                    ));
                }
                match self.validity {
                    Some((start, end)) if start <= end => Ok(()),
                    Some((start, end)) => Err(format!(
                        "verified validity interval is inverted: {start} > {end}"
                    )),
                    None => Err("verified status requires a validity interval".to_string()),
                }
            }
            AttributionStatus::Asserted => {
                let metadata_method =
                    self.method == METHOD_METADATA_FILE || self.method == METHOD_METADATA_LABEL;
                let adapter_method = self.method == METHOD_RUNTIME_ADAPTER;
                if metadata_method || adapter_method {
                    Ok(())
                } else {
                    Err(format!(
                        "asserted status is for metadata/adapter sources, got '{}'",
                        self.method
                    ))
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

    #[test]
    fn verified_requires_method_source_and_interval() {
        let no_interval = AttributionEvidence::new(
            "hook_context",
            "captured_cgroup",
            WorkloadOrigin::KernelCapture,
            AttributionStatus::Verified,
            None,
        );
        assert!(no_interval.validate().is_err());
        let inverted = AttributionEvidence::new(
            "hook_context",
            "captured_cgroup",
            WorkloadOrigin::KernelCapture,
            AttributionStatus::Verified,
            Some((200, 100)),
        );
        assert!(inverted.validate().is_err());
        let wrong_source = AttributionEvidence::new(
            "hook_context",
            "captured_cgroup",
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Verified,
            Some((100, 200)),
        );
        assert!(wrong_source.validate().is_err());
    }

    #[test]
    fn verified_local_binding_is_accepted() {
        let binding =
            AttributionEvidence::verified_local_binding("hook_context", (100, 200));
        assert!(binding.validate().is_ok());
        let capture =
            AttributionEvidence::verified_kernel_capture("hook_context", (100, 200));
        assert!(capture.validate().is_ok());
        let unresolved = AttributionEvidence::unresolved("hook_context");
        assert!(unresolved.validate().is_ok());
    }

    #[test]
    fn metadata_assertion_cannot_self_promote_by_method_or_source() {
        // Borrowing the verified-eligible method with a metadata source.
        let borrowed_method = AttributionEvidence::new(
            "hook_context",
            METHOD_CGROUP_INODE_BIND,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Verified,
            Some((100, 200)),
        );
        assert!(borrowed_method.validate().is_err());
        // Borrowing the verified-eligible source with a metadata method.
        let borrowed_source = AttributionEvidence::new(
            "hook_context",
            METHOD_METADATA_FILE,
            WorkloadOrigin::HostProc,
            AttributionStatus::Verified,
            Some((100, 200)),
        );
        assert!(borrowed_source.validate().is_err());
        // Adapter assertions cap at asserted as well.
        let adapter = AttributionEvidence::new(
            "hook_context",
            METHOD_RUNTIME_ADAPTER,
            WorkloadOrigin::RuntimeAdapter,
            AttributionStatus::Verified,
            Some((100, 200)),
        );
        assert!(adapter.validate().is_err());
        // Honest asserted forms validate.
        assert!(
            AttributionEvidence::asserted_metadata("hook_context", METHOD_METADATA_FILE, None)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn metadata_assertion_cannot_claim_verified() {
        let overclaim = AttributionEvidence::new(
            "hook_context",
            "metadata_file",
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Verified,
            Some((100, 200)),
        );
        assert!(overclaim.validate().is_err());
        let honest = AttributionEvidence::new(
            "hook_context",
            "metadata_file",
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Asserted,
            None,
        );
        assert!(honest.validate().is_ok());
    }
}
