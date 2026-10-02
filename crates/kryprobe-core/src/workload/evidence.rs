// SPDX-License-Identifier: GPL-3.0-or-later
//! Association status and evidence (ADR-0008 §(g)): categorical, never
//! percentages; metadata-file content is asserted until corroborated.

use serde::{Deserialize, Serialize};

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

    /// Validity rules: `Verified` requires the `captured_cgroup` method,
    /// the `KernelCapture` source, plus a well-ordered validity
    /// interval; anything weaker claiming `Verified` is a contradiction
    /// and refuses. Metadata-file content stronger than `Asserted`
    /// without corroboration refuses.
    pub fn validate(&self) -> Result<(), String> {
        if self.relationship.is_empty() || self.method.is_empty() {
            return Err("relationship and method must be non-empty".to_string());
        }
        match self.status {
            AttributionStatus::Verified => {
                if self.method != "captured_cgroup" || self.source != WorkloadOrigin::KernelCapture
                {
                    return Err(format!(
                        "verified status requires captured_cgroup method + kernel_capture source, got '{}' + '{:?}'",
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
                if self.method == "metadata_file" || self.method == "metadata_label" {
                    Ok(())
                } else {
                    Err(format!(
                        "asserted status is for metadata sources, got '{}'",
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
