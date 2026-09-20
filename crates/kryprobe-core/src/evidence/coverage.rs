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

/// Canonical session-coverage dimension (1B-M3): the one enum behind
/// the struct fields, the core spellings, and the kp2 trailer tokens —
/// adding a dimension extends this enum and the compiler points at
/// every projection. (The report renderer's 9 schema dims are a
/// separate frozen contract — the event-v0 `coverage_gap` enum, pinned
/// to the schema file by `coverage_dims.rs` — not these.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverageDimension {
    /// Population the session claims to observe.
    TargetPopulation,
    /// Discovery of executable objects.
    ObjectDiscovery,
    /// Probe attachment to discovered objects.
    Attachment,
    /// Exactness of aggregate counters.
    AggregateCounts,
    /// Completeness of detailed per-operation events.
    DetailedEvents,
    /// Attribution of events to targets/objects/implementations.
    Attribution,
    /// Cross-backend correlation coverage.
    Correlation,
    /// Observation of operation completion.
    Completion,
}

impl CoverageDimension {
    /// All dimensions in struct order.
    pub const ALL: [Self; 8] = [
        Self::TargetPopulation,
        Self::ObjectDiscovery,
        Self::Attachment,
        Self::AggregateCounts,
        Self::DetailedEvents,
        Self::Attribution,
        Self::Correlation,
        Self::Completion,
    ];

    /// Core spelling (matches the `CoverageSummary` field name).
    #[must_use]
    pub const fn as_core_str(self) -> &'static str {
        match self {
            Self::TargetPopulation => "target_population",
            Self::ObjectDiscovery => "object_discovery",
            Self::Attachment => "attachment",
            Self::AggregateCounts => "aggregate_counts",
            Self::DetailedEvents => "detailed_events",
            Self::Attribution => "attribution",
            Self::Correlation => "correlation",
            Self::Completion => "completion",
        }
    }

    /// kp2 §8 trailer token (merged pairs share one token:
    /// `attachment`+`object_discovery` → `attach`,
    /// `aggregate_counts`+`detailed_events` → `capture-integrity`).
    #[must_use]
    pub const fn as_kp2_str(self) -> &'static str {
        match self {
            Self::TargetPopulation => "operation",
            Self::ObjectDiscovery | Self::Attachment => "attach",
            Self::AggregateCounts | Self::DetailedEvents => "capture-integrity",
            Self::Attribution => "attribution",
            Self::Correlation => "correlation",
            Self::Completion => "completion",
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
    /// All-[`CoverageStatus::NotRun`] baseline at the zero wall (no
    /// end, no counters — 1B-H1/1B-L2: the one not-run baseline for
    /// the driver harness and the live finalize context).
    #[must_use]
    pub fn not_run() -> Self {
        let dimension = || {
            DimensionCoverage::new(
                CoverageStatus::NotRun,
                ValidityInterval {
                    start_ns: 0,
                    end_ns: None,
                },
            )
        };
        Self {
            target_population: dimension(),
            object_discovery: dimension(),
            attachment: dimension(),
            aggregate_counts: dimension(),
            detailed_events: dimension(),
            attribution: dimension(),
            correlation: dimension(),
            completion: dimension(),
        }
    }

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

    /// The dimension's coverage record.
    #[must_use]
    pub const fn dimension(&self, dim: CoverageDimension) -> &DimensionCoverage {
        match dim {
            CoverageDimension::TargetPopulation => &self.target_population,
            CoverageDimension::ObjectDiscovery => &self.object_discovery,
            CoverageDimension::Attachment => &self.attachment,
            CoverageDimension::AggregateCounts => &self.aggregate_counts,
            CoverageDimension::DetailedEvents => &self.detailed_events,
            CoverageDimension::Attribution => &self.attribution,
            CoverageDimension::Correlation => &self.correlation,
            CoverageDimension::Completion => &self.completion,
        }
    }

    /// Names of every non-complete dimension, in struct order.
    #[must_use]
    pub fn weaker_dimensions(&self) -> Vec<&'static str> {
        CoverageDimension::ALL
            .iter()
            .filter(|dim| {
                self.dimension(**dim).status != CoverageStatus::CompleteForDeclaredBoundary
            })
            .map(|dim| dim.as_core_str())
            .collect()
    }

    fn statuses(&self) -> [CoverageStatus; 8] {
        CoverageDimension::ALL.map(|dim| self.dimension(dim).status)
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
    fn not_run_coverage_is_all_not_run_at_zero() {
        // 1B-H1/1B-L2: the one all-`NotRun` baseline (driver harness +
        // live finalize context) — zero wall, no end, no counters.
        let coverage = CoverageSummary::not_run();
        for status in coverage.statuses() {
            assert_eq!(status, CoverageStatus::NotRun);
        }
        assert_eq!(coverage.target_population.interval.start_ns, 0);
        assert_eq!(coverage.target_population.interval.end_ns, None);
        assert!(coverage.target_population.counters.is_empty());
    }

    #[test]
    fn dimension_enum_projects_both_spellings() {
        // 1B-M3: one canonical dimension enum — core spellings match
        // the struct fields in order, kp2 spellings match the trailer
        // contract (shared tokens for the merged pairs).
        let core: Vec<&str> = CoverageDimension::ALL
            .iter()
            .map(|dim| dim.as_core_str())
            .collect();
        assert_eq!(
            core,
            vec![
                "target_population",
                "object_discovery",
                "attachment",
                "aggregate_counts",
                "detailed_events",
                "attribution",
                "correlation",
                "completion",
            ]
        );
        let kp2: Vec<&str> = CoverageDimension::ALL
            .iter()
            .map(|dim| dim.as_kp2_str())
            .collect();
        assert_eq!(
            kp2,
            vec![
                "operation",
                "attach",
                "attach",
                "capture-integrity",
                "capture-integrity",
                "attribution",
                "correlation",
                "completion",
            ]
        );
        // The accessor reads the struct field the spelling names.
        let mut coverage = CoverageSummary::not_run();
        coverage.attachment.status = CoverageStatus::Partial;
        assert_eq!(
            coverage.dimension(CoverageDimension::Attachment).status,
            CoverageStatus::Partial
        );
        assert_eq!(
            coverage.dimension(CoverageDimension::Completion).status,
            CoverageStatus::NotRun
        );
    }

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
