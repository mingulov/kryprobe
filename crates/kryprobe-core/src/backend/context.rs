// SPDX-License-Identifier: GPL-3.0-or-later
//! Backend contract context types: borrowed host state per lifecycle step.
//!
//! These are the parameter and result types of the ARCH §4.6 `Backend`
//! trait. Contexts borrow; backends never own session state.

use crate::budget::BudgetManager;
use crate::capability::RuntimeCapabilities;
use crate::enums::BackendId;
use crate::evidence::{CoverageSummary, IntegritySummary};
use crate::ids::{ObjectId, PlanGeneration, SessionId};
use crate::plan::{CapabilityRequirements, OffsetProbe};
use kryprobe_abi::RawEventHeader;
use serde::{Deserialize, Serialize};

/// Borrowed state for [`Backend::detect`](crate::backend::Backend::detect).
#[derive(Debug, Clone, Copy)]
pub struct DetectContext<'a> {
    /// Session being detected for.
    pub session: SessionId,
    /// Probed host capabilities.
    pub runtime: &'a RuntimeCapabilities,
}

/// One backend instance found by detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedInstance {
    /// Backend that detected this instance.
    pub backend: BackendId,
    /// Object file carrying the instance, when known.
    pub object: Option<ObjectId>,
    /// Human-readable detection note; never secrets or target bytes.
    pub detail: String,
}

/// Borrowed state for [`Backend::plan`](crate::backend::Backend::plan).
#[derive(Debug, Clone, Copy)]
pub struct PlanContext<'a> {
    /// Session being planned for.
    pub session: SessionId,
    /// Probed host capabilities.
    pub runtime: &'a RuntimeCapabilities,
}

/// Backend-requested hooks; the runtime validates and attaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendPlan {
    /// Backend requesting these hooks.
    pub backend: BackendId,
    /// Probe points, in attachment order.
    pub probes: Vec<OffsetProbe>,
    /// Capabilities that must hold before attachment.
    pub required: CapabilityRequirements,
}

/// Borrowed state for [`Backend::configure`](crate::backend::Backend::configure).
#[derive(Debug)]
pub struct ConfigureContext<'a> {
    /// Session being configured.
    pub session: SessionId,
    /// Plan generation the backend must honor.
    pub generation: PlanGeneration,
    /// Session budgets; configuration charges links and state entries.
    pub budget: &'a mut BudgetManager,
}

/// Borrowed state for [`Backend::decode`](crate::backend::Backend::decode).
#[derive(Debug, Clone, Copy)]
pub struct DecodeContext<'a> {
    /// Session the event belongs to.
    pub session: SessionId,
    /// Plan generation valid for this event.
    pub generation: PlanGeneration,
    /// Current integrity baseline for loss-aware decoding.
    pub integrity: &'a IntegritySummary,
}

/// One raw BPF event: validated header plus backend-owned payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEvent<'a> {
    /// Validated common header (CONTRACTS §3).
    pub header: RawEventHeader,
    /// Backend-owned payload; the backend validates its shape.
    pub payload: &'a [u8],
}

/// Borrowed state for [`Backend::finalize`](crate::backend::Backend::finalize).
#[derive(Debug, Clone, Copy)]
pub struct FinalizeContext<'a> {
    /// Session being finalized.
    pub session: SessionId,
    /// Session coverage for the backend's final assessment.
    pub coverage: &'a CoverageSummary,
    /// Session integrity for the backend's final assessment.
    pub integrity: &'a IntegritySummary,
}

/// Per-backend end-of-session facts: counts plus integrity receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSummary {
    /// Backend reporting.
    pub backend: BackendId,
    /// Observations decoded by this backend (JSON string on the wire).
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub observations: u64,
    /// Integrity counters attributed to this backend.
    pub integrity: IntegritySummary,
}
