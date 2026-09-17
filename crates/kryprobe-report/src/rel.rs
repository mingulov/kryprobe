// SPDX-License-Identifier: GPL-3.0-or-later
//! Derived records: `relationship`.
//!
//! The only relationship kind (`SynchronousNestedExecution`) spells
//! `nested_within`. All seven CONTRACTS §10 evidence prerequisites anchor
//! verified synchronous nesting; anything less is a qualified lifetime.

use crate::writer::{JsonlWriter, ReportError};
use kryprobe_core::evidence::{RelationshipConfidence, RelationshipRecord};
use serde::Serialize;

/// CONTRACTS §10 prerequisite count for verified synchronous nesting.
const FULL_EVIDENCE: usize = 7;

#[derive(Serialize)]
struct RelPayload<'a> {
    parent_observation_id: String,
    child_observation_id: String,
    relation: &'static str,
    anchor: &'static str,
    rule_id: &'a str,
    integrity: &'static str,
}

impl JsonlWriter {
    /// Appends `relationship`; full evidence anchors verified nesting.
    pub fn relationship(
        &mut self,
        rel: &RelationshipRecord,
        rule_id: &str,
    ) -> Result<(), ReportError> {
        let anchor = if rel.evidence.len() == FULL_EVIDENCE {
            "verified_synchronous_nesting"
        } else {
            "qualified_context_lifetime"
        };
        let integrity = match rel.confidence {
            RelationshipConfidence::Qualified => "qualified",
            RelationshipConfidence::Partial => "partial",
            RelationshipConfidence::Unknown => "unknown",
        };
        self.emit(
            "relationship",
            RelPayload {
                parent_observation_id: rel.parent.to_string(),
                child_observation_id: rel.child.to_string(),
                relation: "nested_within",
                anchor,
                rule_id,
                integrity,
            },
        );
        Ok(())
    }
}
