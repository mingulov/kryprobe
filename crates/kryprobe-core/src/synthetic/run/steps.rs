// SPDX-License-Identifier: GPL-3.0-or-later
//! Script steps: op vocabulary plus open/close/spawn transitions.
//!
//! Sibling of the renderer in `run.rs`: steps mutate [`Runner`] state,
//! the renderer only stamps records.

use super::{Runner, defect, outcome_of};
use crate::enums::{CallKind, EvidencePhase, OperationClass};
use crate::error::BackendError;
use crate::evidence::{
    RelationshipConfidence, RelationshipEvidence, RelationshipKind, RelationshipRecord,
};
use crate::ids::{CorrelationId, ObservationId};
use serde_json::json;

/// Operation shape shared by one scripted Enter/Return pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpSpec {
    /// Cryptographic operation class.
    pub class: OperationClass,
    /// API-shape classification of the call.
    pub call: CallKind,
}

/// One scripted step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptOp {
    /// Open an observation (emits discovered/selected/entered).
    Enter {
        /// Operation being entered.
        op: OpSpec,
    },
    /// Close an observation with a native code.
    Return {
        /// Operation being returned from.
        op: OpSpec,
        /// Scripted native return code (0 = success).
        code: i32,
    },
    /// Lose detailed events while aggregate counts stay exact.
    DropDetailed {
        /// Number of detailed events lost.
        count: u64,
    },
    /// Spawn a child observation still running at session end.
    SpawnChild {
        /// Open observation the child nests within.
        parent: ObservationId,
    },
}

impl Runner {
    /// Open one observation through discovered/selected/entered.
    pub(super) fn enter(&mut self, spec: OpSpec) -> Result<ObservationId, BackendError> {
        let id = ObservationId::new(self.next_observation);
        self.next_observation += 1;
        let opened_ns = self.clock.now();
        for phase in [
            EvidencePhase::Discovered,
            EvidencePhase::Selected,
            EvidencePhase::Entered,
        ] {
            self.emit_phase(id, opened_ns, spec, phase, "pending", 0)?;
        }
        self.open.push(super::OpenOp {
            spec,
            id,
            opened_ns,
        });
        Ok(id)
    }

    /// Close one observation; size queries stop at returned, failures at
    /// completed, successes add the completed+success rendering.
    pub(super) fn return_op(&mut self, spec: OpSpec, code: i32) -> Result<(), BackendError> {
        let position = self
            .open
            .iter()
            .position(|open| open.spec == spec)
            .ok_or_else(|| defect("return without open enter"))?;
        let open = self.open.remove(position);
        let outcome = outcome_of(code);
        self.emit_phase(
            open.id,
            open.opened_ns,
            spec,
            EvidencePhase::Returned,
            outcome,
            code,
        )?;
        if spec.call == CallKind::SizeQuery {
            return Ok(());
        }
        self.emit_phase(
            open.id,
            open.opened_ns,
            spec,
            EvidencePhase::Completed,
            outcome,
            code,
        )?;
        if code == 0 {
            self.emit_phase(
                open.id,
                open.opened_ns,
                spec,
                EvidencePhase::Completed,
                "success",
                code,
            )?;
        }
        Ok(())
    }

    /// Spawn a child that is still running when the session ends.
    pub(super) fn spawn_child(&mut self, parent: ObservationId) -> Result<(), BackendError> {
        let spec = OpSpec {
            class: OperationClass::Sign,
            call: CallKind::Operation,
        };
        let child = self.enter(spec)?;
        let id = CorrelationId::new(self.next_relationship);
        self.next_relationship += 1;
        self.relationships.push(RelationshipRecord {
            id,
            kind: RelationshipKind::SynchronousNestedExecution,
            parent,
            child,
            confidence: RelationshipConfidence::Qualified,
            evidence: vec![
                RelationshipEvidence::SameProcessGeneration,
                RelationshipEvidence::SameExecutionContext,
            ],
            limitations: Vec::new(),
        });
        self.push(
            "synthetic_relationship",
            json!({
                "parent_observation_id": parent.to_string(),
                "child_observation_id": child.to_string(),
                "relation": "nested_within",
                "anchor": "verified_synchronous_nesting",
                "rule_id": "synthetic-spawn-v0",
                "integrity": "qualified",
            }),
        );
        Ok(())
    }
}
