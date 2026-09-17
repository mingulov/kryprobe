// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic scripted backend: deterministic sessions without BPF.
//!
//! Drives scripted operation sequences through the session contract so the
//! runtime, reporting, and CLI are testable with byte-exact goldens. All
//! JSONL output uses schema-spelled values only.

pub mod codec;
pub mod run;

pub use run::{OpSpec, ScriptOp, ScriptRun};

use crate::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendSummary, ConfigureContext, DecodeContext,
    DetectContext, DetectedInstance, FinalizeContext, PlanContext, RawEvent,
};
use crate::budget::BudgetKind;
use crate::enums::{BackendId, CaptureMode};
use crate::error::{BackendError, BudgetReason, UnsupportedReason};
use crate::evidence::{IntegrityRef, NativeObservation, NativeResult};
use crate::ids::ObservationId;
use crate::plan::{CapabilityRequirements, OffsetProbe};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Static descriptor: synthetic backend asks for no host capabilities.
static SYNTHETIC_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    backend: BackendId::Synthetic,
    name: "synthetic",
    required: CapabilityRequirements {
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf: false,
    },
};

/// Scripted backend: replays a fixed op sequence deterministically.
#[derive(Debug)]
pub struct SyntheticBackend {
    script: Vec<ScriptOp>,
    decoded: AtomicUsize,
}

impl SyntheticBackend {
    /// Backend replaying `script` in order.
    #[must_use]
    pub fn new(script: Vec<ScriptOp>) -> Self {
        Self {
            script,
            decoded: AtomicUsize::new(0),
        }
    }

    /// Encode one scripted event payload (8 bytes, versioned, total).
    #[must_use]
    pub fn encode_event(
        phase: crate::enums::EvidencePhase,
        class: crate::enums::OperationClass,
        call: crate::enums::CallKind,
        code: i32,
    ) -> [u8; 8] {
        codec::encode_event(phase, class, call, code)
    }
}

impl Backend for SyntheticBackend {
    fn id(&self) -> BackendId {
        BackendId::Synthetic
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        &SYNTHETIC_CAPABILITIES
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        Ok(vec![DetectedInstance {
            backend: BackendId::Synthetic,
            object: None,
            detail: String::from("synthetic scripted instance"),
        }])
    }

    fn plan(
        &self,
        _ctx: &PlanContext<'_>,
        _instance: &DetectedInstance,
        _mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError> {
        Ok(BackendPlan {
            backend: BackendId::Synthetic,
            probes: vec![
                OffsetProbe {
                    file_offset: 0x1000,
                    cookie: 0,
                    descriptor_id: 0,
                },
                OffsetProbe {
                    file_offset: 0x1010,
                    cookie: 1,
                    descriptor_id: 1,
                },
                OffsetProbe {
                    file_offset: 0x1020,
                    cookie: 2,
                    descriptor_id: 2,
                },
            ],
            required: CapabilityRequirements::default(),
        })
    }

    fn configure(
        &self,
        ctx: &mut ConfigureContext<'_>,
        plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        let links = plan.probes.len() as u64;
        charge(ctx, BudgetKind::Links, links)?;
        charge(ctx, BudgetKind::StateEntries, links)?;
        Ok(())
    }

    fn decode(
        &self,
        _ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        let (phase, class, call, code) = codec::decode_event(&event)?;
        let id = self.decoded.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(NativeObservation {
            id: ObservationId::new(id as u64),
            backend: BackendId::Synthetic,
            target: None,
            object: None,
            implementation: None,
            phase,
            call_kind: call,
            operation_class: class,
            native_name: None,
            native_code: None,
            native_result: NativeResult::Synthetic { code },
            started_ns: Some(event.header.monotonic_ns),
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::Value::Null,
        })
    }

    fn finalize(&self, ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        Ok(BackendSummary {
            backend: BackendId::Synthetic,
            observations: self.decoded.load(Ordering::SeqCst) as u64,
            integrity: *ctx.integrity,
        })
    }
}

/// Charge one budget kind, mapping refusal to a typed exhaustion error.
fn charge(
    ctx: &mut ConfigureContext<'_>,
    kind: BudgetKind,
    amount: u64,
) -> Result<(), BackendError> {
    ctx.budget.charge(kind, amount).map_err(|omission| {
        let name = match kind {
            BudgetKind::Links => "links",
            BudgetKind::StateEntries => "state_entries",
            _ => "budget",
        };
        BackendError::Exhausted(BudgetReason::with_detail(name, &omission.to_string()))
    })
}

/// Barrier and loss event kinds are outside the synthetic decoder.
pub(crate) fn unsupported_kind(reason: &'static str) -> BackendError {
    BackendError::Unsupported(UnsupportedReason::new(reason))
}
