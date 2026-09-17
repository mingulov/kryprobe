// SPDX-License-Identifier: GPL-3.0-or-later
//! Correlation contract: derived relationships between observations.
//!
//! Follows CONTRACTS §10. Timestamp adjacency alone never justifies a
//! relationship; every record carries its evidence and limitations.

use crate::evidence::OmissionId;
use crate::ids::{CorrelationId, ObservationId};
use serde::{Deserialize, Serialize};

/// Allowed relationship kind; exactly one exists initially.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    /// Child executed synchronously nested inside the parent.
    SynchronousNestedExecution,
}

/// Confidence classification of a derived relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipConfidence {
    /// All required evidence present and valid.
    Qualified,
    /// Derived with recorded gaps; see `limitations`.
    Partial,
    /// Confidence could not be determined.
    Unknown,
}

/// One prerequisite fact backing a relationship (CONTRACTS §10 list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipEvidence {
    /// Parent and child share a process generation.
    SameProcessGeneration,
    /// Parent and child share a thread/execution context.
    SameExecutionContext,
    /// Parent and child share a BPF operation-stack frame/correlation ID.
    SharedCorrelationFrame,
    /// Nesting state valid and non-overflowed.
    ValidNestingState,
    /// Plan generations valid for both boundaries.
    ValidPlanGenerations,
    /// No known nonlocal-exit/cleanup break between parent and child.
    NoNonlocalExitBreak,
    /// Both native observations independently valid.
    IndependentlyValidObservations,
}

/// Derived relationship between two native observations (CONTRACTS §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationshipRecord {
    /// Session-scoped relationship identity.
    pub id: CorrelationId,
    /// Relationship kind.
    pub kind: RelationshipKind,
    /// Outer observation.
    pub parent: ObservationId,
    /// Inner observation.
    pub child: ObservationId,
    /// Confidence classification.
    pub confidence: RelationshipConfidence,
    /// Prerequisite facts backing this relationship.
    pub evidence: Vec<RelationshipEvidence>,
    /// Known gaps qualifying this relationship.
    pub limitations: Vec<OmissionId>,
}
