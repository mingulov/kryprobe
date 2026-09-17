// SPDX-License-Identifier: GPL-3.0-or-later
//! Coverage model: eight dimensions, weakest-link summary only.
//!
//! Follows CONTRACTS §8. There is deliberately no optimistic global FULL:
//! [`CoverageSummary::overall`] reports the weakest dimension, and
//! [`CoverageSummary::weaker_dimensions`] names every non-complete one.

use crate::enums::{BackendId, CoverageStatus};
use crate::evidence::{OmissionId, ValidityInterval};
use crate::ids::{ObjectId, PlanGeneration, TargetId};
use serde::{Deserialize, Serialize};

/// One supporting counter/receipt attached to a dimension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DimensionCounter {
    /// Counter name (e.g. `"probes_attached"`).
    pub name: String,
    /// Counter value (JSON string on the wire).
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub value: u64,
}

/// Coverage of one dimension (CONTRACTS §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionCoverage {
    /// Status within the declared boundary.
    pub status: CoverageStatus,
    /// Validity interval of this assessment.
    pub interval: ValidityInterval,
    /// Explicit omissions/reasons.
    pub omissions: Vec<OmissionId>,
    /// Backends this dimension covers.
    pub affected_backends: Vec<BackendId>,
    /// Targets this dimension covers.
    pub affected_targets: Vec<TargetId>,
    /// Objects this dimension covers.
    pub affected_objects: Vec<ObjectId>,
    /// Plan generation assessed, when applicable.
    pub plan: Option<PlanGeneration>,
    /// Supporting counters/receipts.
    pub counters: Vec<DimensionCounter>,
}

impl DimensionCoverage {
    /// Dimension with status and interval; empty scope, omissions, counters.
    #[must_use]
    pub fn new(status: CoverageStatus, interval: ValidityInterval) -> Self {
        Self {
            status,
            interval,
            omissions: Vec::new(),
            affected_backends: Vec::new(),
            affected_targets: Vec::new(),
            affected_objects: Vec::new(),
            plan: None,
            counters: Vec::new(),
        }
    }
}

/// Eight-dimension session coverage (CONTRACTS §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    /// Population the session claims to observe.
    pub target_population: DimensionCoverage,
    /// Discovery of executable objects.
    pub object_discovery: DimensionCoverage,
    /// Probe attachment to discovered objects.
    pub attachment: DimensionCoverage,
    /// Exactness of aggregate counters.
    pub aggregate_counts: DimensionCoverage,
    /// Completeness of detailed per-operation events.
    pub detailed_events: DimensionCoverage,
    /// Attribution of events to targets/objects/implementations.
    pub attribution: DimensionCoverage,
    /// Cross-backend correlation coverage.
    pub correlation: DimensionCoverage,
    /// Observation of operation completion.
    pub completion: DimensionCoverage,
}

impl CoverageSummary {
    /// Weakest-link summary: the worst dimension status wins. Only an
    /// all-complete session reports `CompleteForDeclaredBoundary`.
    #[must_use]
    pub fn overall(&self) -> CoverageStatus {
        self.statuses().iter().fold(
            CoverageStatus::CompleteForDeclaredBoundary,
            |worst, status| {
                if rank(*status) > rank(worst) {
                    *status
                } else {
                    worst
                }
            },
        )
    }

    /// Names of every non-complete dimension, in struct order.
    #[must_use]
    pub fn weaker_dimensions(&self) -> Vec<&'static str> {
        const NAMES: [&str; 8] = [
            "target_population",
            "object_discovery",
            "attachment",
            "aggregate_counts",
            "detailed_events",
            "attribution",
            "correlation",
            "completion",
        ];
        self.statuses()
            .iter()
            .zip(NAMES)
            .filter(|(status, _)| **status != CoverageStatus::CompleteForDeclaredBoundary)
            .map(|(_, name)| name)
            .collect()
    }

    fn statuses(&self) -> [CoverageStatus; 8] {
        [
            self.target_population.status,
            self.object_discovery.status,
            self.attachment.status,
            self.aggregate_counts.status,
            self.detailed_events.status,
            self.attribution.status,
            self.correlation.status,
            self.completion.status,
        ]
    }
}

/// Severity rank: definitive-but-bounded `Unsupported` outranks lossy
/// `Partial`; `NotRun`/`Unknown` carry the least evidence and rank worst.
const fn rank(status: CoverageStatus) -> u8 {
    match status {
        CoverageStatus::CompleteForDeclaredBoundary => 0,
        CoverageStatus::Unsupported => 1,
        CoverageStatus::Partial => 2,
        CoverageStatus::NotRun => 3,
        CoverageStatus::Unknown => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_order_is_pinned() {
        // Load-bearing order for `overall()`: higher rank = weaker.
        // Unsupported (definitive, bounded) outranks Partial (lossy).
        let ordered = [
            CoverageStatus::CompleteForDeclaredBoundary,
            CoverageStatus::Unsupported,
            CoverageStatus::Partial,
            CoverageStatus::NotRun,
            CoverageStatus::Unknown,
        ];
        for (i, status) in ordered.iter().enumerate() {
            assert_eq!(rank(*status), i as u8, "rank of {status:?} moved");
        }
    }
}
