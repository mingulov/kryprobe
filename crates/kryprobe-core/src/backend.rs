// SPDX-License-Identifier: GPL-3.0-or-later
//! Backend contract: host-side trait plus owned registry and driver.
//!
//! The [`Backend`] trait is exactly ARCH §4.6. ARCH writes `Result` bare;
//! the error type is [`BackendError`] per CONTRACTS §14 ("Backends return
//! typed errors").

pub mod context;
pub mod driver;
pub mod registry;

pub use context::{
    BackendPlan, BackendSummary, ConfigureContext, DecodeContext, DetectContext, DetectedInstance,
    FinalizeContext, PlanContext, RawEvent,
};
pub use driver::{BackendDriver, DriverError, DriverReport, SharedFeedError, SkippedBackend};
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
///
/// # Example
///
/// A minimal backend: static identity, no instances, empty plans.
///
/// ```
/// use kryprobe_core::backend::{
///     Backend, BackendCapabilities, BackendPlan, BackendSummary, ConfigureContext, DecodeContext,
///     DetectContext, DetectedInstance, FinalizeContext, PlanContext, RawEvent,
/// };
/// use kryprobe_core::enums::{BackendId, CaptureMode};
/// use kryprobe_core::error::{BackendError, InputReason};
/// use kryprobe_core::evidence::{IntegritySummary, NativeObservation};
/// use kryprobe_core::plan::CapabilityRequirements;
///
/// struct NullBackend;
///
/// static CAPS: BackendCapabilities = BackendCapabilities {
///     backend: BackendId::Synthetic,
///     name: "null",
///     required: CapabilityRequirements {
///         uprobe_multi: false,
///         cookies: false,
///         ringbuf: false,
///         btf: false,
///     },
/// };
///
/// impl Backend for NullBackend {
///     fn id(&self) -> BackendId {
///         BackendId::Synthetic
///     }
///     fn capabilities(&self) -> &'static BackendCapabilities {
///         &CAPS
///     }
///     fn detect(
///         &self,
///         _ctx: &DetectContext<'_>,
///     ) -> Result<Vec<DetectedInstance>, BackendError> {
///         Ok(Vec::new())
///     }
///     fn plan(
///         &self,
///         _ctx: &PlanContext<'_>,
///         instance: &DetectedInstance,
///         _mode: CaptureMode,
///     ) -> Result<BackendPlan, BackendError> {
///         Ok(BackendPlan {
///             backend: instance.backend,
///             probes: Vec::new(),
///             required: CapabilityRequirements::default(),
///         })
///     }
///     fn configure(
///         &self,
///         _ctx: &mut ConfigureContext<'_>,
///         _plan: &BackendPlan,
///     ) -> Result<(), BackendError> {
///         Ok(())
///     }
///     fn decode(
///         &self,
///         _ctx: &DecodeContext<'_>,
///         _event: RawEvent<'_>,
///     ) -> Result<NativeObservation, BackendError> {
///         Err(BackendError::CorruptInput(InputReason::new("null backend")))
///     }
///     fn finalize(
///         &self,
///         _ctx: &FinalizeContext<'_>,
///     ) -> Result<BackendSummary, BackendError> {
///         Ok(BackendSummary {
///             backend: BackendId::Synthetic,
///             observations: 0,
///             integrity: IntegritySummary::default(),
///         })
///     }
/// }
///
/// assert_eq!(NullBackend.id(), BackendId::Synthetic);
/// ```
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
    /// Records driver-side output-budget omissions (decoded records
    /// the driver dropped after taking them). Called before
    /// `finalize`; the backend attests the count via
    /// `budget_omissions` instead of silently omitting completed
    /// work. The default ignores the report (backends whose drivers
    /// never cap output); backends WITH a capping driver MUST
    /// override — a missing override plus a capping driver drops
    /// evidence silently, so the driver's cap test pins the
    /// attested count end to end.
    fn note_output_omissions(&self, _omitted: u64) {}
}
