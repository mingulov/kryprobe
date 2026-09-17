// SPDX-License-Identifier: GPL-3.0-or-later
//! Scripted session runner: deterministic op sequences to golden JSONL.
//!
//! One record advances the manual clock by exactly 1000ns, so output is
//! byte-deterministic for a fixed script. Dropped detail bumps
//! `ring_reservation_failures` while `aggregate_observations` stays exact
//! (emitted observations plus dropped detail).

use crate::enums::EvidencePhase;
use crate::error::{BackendError, InternalError};
use crate::evidence::{IntegritySummary, NativeResult, RelationshipRecord};
use crate::ids::{ObservationId, SessionId};
use kryprobe_testkit::ManualClock;
use serde_json::{Value, json};

mod steps;

pub use steps::{OpSpec, ScriptOp, canonical_script};

/// Deterministic outcome of one scripted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptRun {
    /// Emitted JSONL records, in clock order.
    records: Vec<Value>,
    /// Derived relationships.
    pub relationships: Vec<RelationshipRecord>,
    /// Session integrity receipts.
    pub integrity: IntegritySummary,
    /// Exact observation count: emitted plus dropped detail.
    pub aggregate_observations: u64,
}

impl ScriptRun {
    /// Render records as newline-terminated JSONL.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut text = String::new();
        for record in &self.records {
            text.push_str(&record.to_string());
            text.push('\n');
        }
        text
    }
}

/// Clock step per emitted record, in monotonic nanoseconds.
const STEP_NS: u64 = 1_000;

/// Open observation tracked while its Enter lacks a Return.
struct OpenOp {
    spec: OpSpec,
    id: ObservationId,
    opened_ns: u64,
}

/// Per-record render state threaded through the script.
struct Runner {
    session: SessionId,
    clock: ManualClock,
    next_observation: u64,
    next_relationship: u64,
    open: Vec<OpenOp>,
    records: Vec<Value>,
    relationships: Vec<RelationshipRecord>,
    integrity: IntegritySummary,
    dropped: u64,
    emitted_observations: u64,
}

impl Runner {
    fn new(session: SessionId) -> Self {
        Self {
            session,
            clock: ManualClock::new(1_000_000),
            next_observation: 1,
            next_relationship: 1,
            open: Vec::new(),
            records: Vec::new(),
            relationships: Vec::new(),
            integrity: IntegritySummary::default(),
            dropped: 0,
            emitted_observations: 0,
        }
    }

    /// Stamp one envelope and advance the clock exactly one step.
    fn push(&mut self, kind: &str, payload: Value) {
        let index = self.records.len() as u64;
        self.records.push(json!({
            "schema": "kryprobe.event/v0",
            "kind": kind,
            "session_id": self.session.to_string(),
            "record_id": format!("synthetic:{index}"),
            "monotonic_ns": self.clock.now().to_string(),
            "payload": payload,
        }));
        self.clock.advance(STEP_NS);
    }

    /// Emit one observation phase record.
    fn emit_phase(
        &mut self,
        id: ObservationId,
        opened_ns: u64,
        spec: OpSpec,
        phase: EvidencePhase,
        outcome: &str,
        code: i32,
    ) -> Result<(), BackendError> {
        let Some(phase_wire) = phase.as_wire_str() else {
            return Err(defect("internal phase reached the renderer"));
        };
        let class = wire_value(&spec.class)?;
        let call = wire_value(&spec.call)?;
        let native = wire_value(&NativeResult::Synthetic { code })?;
        self.push(
            "synthetic_observation",
            json!({
                "observation_id": id.to_string(),
                "phase": phase_wire,
                "call_kind": call,
                "operation_class": class,
                "outcome": outcome,
                "native_result": native,
                "duration_ns": self.clock.now().saturating_sub(opened_ns).to_string(),
            }),
        );
        self.emitted_observations += 1;
        Ok(())
    }

    /// Seal the run: unmatched entries plus exact aggregates.
    fn finish(mut self) -> ScriptRun {
        self.integrity.unmatched_entries += self.open.len() as u64;
        let aggregate_observations = self.emitted_observations + self.dropped;
        ScriptRun {
            records: self.records,
            relationships: self.relationships,
            integrity: self.integrity,
            aggregate_observations,
        }
    }
}

impl crate::synthetic::SyntheticBackend {
    /// Replay the script for one session, deterministically.
    pub fn run_script(&self, session: SessionId) -> Result<ScriptRun, BackendError> {
        let mut runner = Runner::new(session);
        for op in &self.script {
            match *op {
                ScriptOp::Enter { op } => {
                    runner.enter(op)?;
                }
                ScriptOp::Return { op, code } => {
                    runner.return_op(op, code)?;
                }
                ScriptOp::DropDetailed { count } => {
                    runner.integrity.ring_reservation_failures += count;
                    runner.dropped += count;
                }
                ScriptOp::SpawnChild { parent } => {
                    runner.spawn_child(parent)?;
                }
            }
        }
        Ok(runner.finish())
    }
}

/// Outcome spelling for a native return code.
fn outcome_of(code: i32) -> &'static str {
    if code == 0 { "success" } else { "failure" }
}

/// Script bugs are harness defects, never caller errors.
fn defect(reason: &'static str) -> BackendError {
    BackendError::Internal(InternalError::new(reason))
}

/// Serialize one wire value; serialization failure is a harness defect.
fn wire_value<T: serde::Serialize>(value: &T) -> Result<Value, BackendError> {
    serde_json::to_value(value).map_err(|_| defect("wire value failed to serialize"))
}
