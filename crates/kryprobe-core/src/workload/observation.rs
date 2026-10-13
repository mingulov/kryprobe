// SPDX-License-Identifier: GPL-3.0-or-later
//! Enriched workload observations (ADR-0008 §(g), Stage 2A contract):
//! one captured context plus its workload identity and evidence. The
//! shared enrichment row consumed by Stage 2C/2D report assembly and
//! scoped policy evaluation.
//!
//! Pure by construction: no OS reads, no I/O, no ambient clocks.

use super::{AttributionEvidence, MetadataUnavailable};
use super::{AttributionStatus, ContextIdentity, MAX_STRING_FIELD_BYTES, WorkloadIdentity};
use serde::{Deserialize, Serialize};

/// One captured execution context with its resolved workload identity
/// and the evidence for the association.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadObservation {
    /// The captured kernel/session context.
    pub context: ContextIdentity,
    /// The workload identity established for it (possibly none).
    pub identity: WorkloadIdentity,
    /// The evidence for the association.
    pub evidence: AttributionEvidence,
}

impl WorkloadObservation {
    /// Observation rules: the evidence validates, the identity fits the
    /// string budget and is cluster-consistent, identity and status
    /// cohere — resolved identities carry usable statuses
    /// (verified/asserted/stale) while unresolved identities carry
    /// unusable ones (unresolved/ambiguous/unsupported) — and a
    /// cgroup-zero context carries no resolved identity: the
    /// unknown-cgroup population never resolves, whatever a received
    /// row claims (SEM02, mirroring `SnapshotResponse`).
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        self.evidence
            .validate()
            .map_err(|_| MetadataUnavailable::ParseFailed)?;
        if !self.identity.check_bounds(MAX_STRING_FIELD_BYTES) {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        if !self.identity.check_consistency() {
            return Err(MetadataUnavailable::ParseFailed);
        }
        let usable = matches!(
            self.evidence.status,
            AttributionStatus::Verified | AttributionStatus::Asserted | AttributionStatus::Stale
        );
        if usable != self.identity.is_resolved() {
            return Err(MetadataUnavailable::ParseFailed);
        }
        if self.context.cgroup == 0 && self.identity.is_resolved() {
            return Err(MetadataUnavailable::ParseFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{METHOD_METADATA_FILE, Relationship, ValidityInterval};
    use super::*;

    fn context() -> ContextIdentity {
        ContextIdentity::new(7, 43812, 1000, 1000, 555, super::super::ExecutionKind::Proc)
    }

    #[test]
    fn asserted_observation_with_identity_validates() {
        let observation = WorkloadObservation {
            context: context(),
            identity: WorkloadIdentity::container("rt", "id", Some("life")),
            evidence: AttributionEvidence::asserted_metadata(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                Some(ValidityInterval::monotonic(100, 200)),
            ),
        };
        assert!(observation.validate().is_ok());
    }

    #[test]
    fn unresolved_observation_without_identity_validates() {
        let observation = WorkloadObservation {
            context: context(),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::unresolved(Relationship::HookContext),
        };
        assert!(observation.validate().is_ok());
    }

    #[test]
    fn cgroup_zero_with_identity_refuses() {
        // SEM02: cgroup 0 is the unreadable marker — it carries no
        // resolved identity, whatever usable status the evidence
        // claims. Mirrors the SnapshotResponse ingress rule so every
        // report/policy ingress agrees.
        let usable = [
            AttributionEvidence::verified_kernel_capture(
                Relationship::HookContext,
                ValidityInterval::monotonic(100, 200),
            ),
            AttributionEvidence::asserted_metadata(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                Some(ValidityInterval::monotonic(100, 200)),
            ),
            AttributionEvidence::new(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                super::super::WorkloadOrigin::OperatorMetadataFile,
                AttributionStatus::Stale,
                Some(ValidityInterval::monotonic(100, 200)),
            ),
        ];
        for evidence in &usable {
            assert!(evidence.validate().is_ok(), "usable evidence is coherent");
            let bad = WorkloadObservation {
                context: ContextIdentity::new(
                    7,
                    0,
                    1000,
                    1000,
                    555,
                    super::super::ExecutionKind::Proc,
                ),
                identity: WorkloadIdentity::container("rt", "id", Some("life")),
                evidence: evidence.clone(),
            };
            assert!(
                bad.validate().is_err(),
                "resolved cgroup-zero refuses under {evidence:?}"
            );
        }
        // Positive controls: unresolved cgroup-zero stays valid, and an
        // ordinary resolved row is unaffected.
        let unresolved_zero = WorkloadObservation {
            context: ContextIdentity::new(7, 0, 1000, 1000, 555, super::super::ExecutionKind::Proc),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::unresolved(Relationship::HookContext),
        };
        assert!(unresolved_zero.validate().is_ok());
        let ordinary = WorkloadObservation {
            context: context(),
            identity: WorkloadIdentity::container("rt", "id", Some("life")),
            evidence: AttributionEvidence::asserted_metadata(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                Some(ValidityInterval::monotonic(100, 200)),
            ),
        };
        assert!(ordinary.validate().is_ok());
    }

    #[test]
    fn identity_status_mismatch_refuses() {
        // Resolved identity with an unusable status.
        let bad = WorkloadObservation {
            context: context(),
            identity: WorkloadIdentity::container("rt", "id", Some("life")),
            evidence: AttributionEvidence::unresolved(Relationship::HookContext),
        };
        assert!(bad.validate().is_err());
        // Usable status without an identity.
        let bad = WorkloadObservation {
            context: context(),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::asserted_metadata(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                None,
            ),
        };
        assert!(bad.validate().is_err());
    }
}
