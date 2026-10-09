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
    /// string budget and is cluster-consistent, and identity and status
    /// cohere — resolved identities carry usable statuses
    /// (verified/asserted/stale) while unresolved identities carry
    /// unusable ones (unresolved/ambiguous/unsupported).
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
