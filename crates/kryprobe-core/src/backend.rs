// SPDX-License-Identifier: GPL-3.0-or-later
//! Backend contract: host-side trait plus static registry.
//!
//! The [`Backend`] trait is exactly ARCH §4.6. ARCH writes `Result` bare;
//! the error type is [`BackendError`] per CONTRACTS §14 ("Backends return
//! typed errors").

pub mod context;
pub mod registry;

pub use context::{
    BackendPlan, BackendSummary, ConfigureContext, DecodeContext, DetectContext, DetectedInstance,
    FinalizeContext, PlanContext, RawEvent,
};
pub use registry::{BackendRegistry, DuplicateBackend};

use crate::enums::{BackendId, CaptureMode};
use crate::error::BackendError;
use crate::evidence::NativeObservation;
use crate::plan::CapabilityRequirements;
use serde::Serialize;

/// Static backend descriptor: identity plus attachment gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BackendCapabilities {
    /// Backend described.
    pub backend: BackendId,
    /// Static backend name for evidence/debugging.
    pub name: &'static str,
    /// Capabilities that must have probed present before attachment.
    pub required: CapabilityRequirements,
}

/// Host-side backend contract (ARCH §4.6).
///
/// A backend detects and interprets its own domain, requests hooks through
/// a plan instead of attaching directly, and emits native facts plus
/// coverage/integrity facts. It never creates links, never inspects
/// arbitrary targets, never mutates another backend's state, and never
/// claims global session completeness.
pub trait Backend: Send + Sync {
    /// Backend identity; the registry key.
    fn id(&self) -> BackendId;
    /// Static descriptor; gates attachment.
    fn capabilities(&self) -> &'static BackendCapabilities;
    /// Detect instances of this backend's domain.
    fn detect(&self, ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError>;
    /// Request hooks for one detected instance and capture mode.
    fn plan(
        &self,
        ctx: &PlanContext<'_>,
        instance: &DetectedInstance,
        mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError>;
    /// Apply a plan: charge budgets and prepare backend state.
    fn configure(
        &self,
        ctx: &mut ConfigureContext<'_>,
        plan: &BackendPlan,
    ) -> Result<(), BackendError>;
    /// Decode one raw event into a native observation.
    ///
    /// The observation ID comes from `ctx.id_issuer`: backends must
    /// never mint IDs from private counters (two backends would
    /// collide in one session).
    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError>;
    /// Report end-of-session facts for this backend.
    fn finalize(&self, ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError>;
}
