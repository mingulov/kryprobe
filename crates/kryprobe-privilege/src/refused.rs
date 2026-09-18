// SPDX-License-Identifier: GPL-3.0-or-later
//! Refused token/broker authority stub (SECURITY §3, R-030).
//!
//! `TokenBrokerStub` keeps the pre-facet broker call-site shape (whole-plan
//! `attach_plan`, `BackendError::Unsupported` receipts) so future
//! broker-mode call sites typecheck, but every method refuses with the
//! R-030 receipt pointer. There is no partial broker path: token mode
//! arrives with pack experiment T6 + Phase B receipts.
//!
//! Deliberately NOT a facet implementation (R4 legacy verdict): the local
//! entries moved onto the `BpfLoad`/`Attach`/`TargetInspection` facet
//! traits (T5), whose error types cannot carry a mode refusal honestly —
//! `LoaderError::NotAllowed` means "forbidden program" (X16) and
//! `InspectError` only knows gone/denied — so implementing the facets
//! would either lie about the failure or widen shared error contracts
//! for a stub with no callers (only its own tests reference it). When
//! Phase B lands, the broker gets real facet implementations and this
//! stub is deleted; until then it pins "refuse everything with R-030".

use kryprobe_core::ProgramId;
use kryprobe_core::error::{BackendError, UnsupportedReason};
use kryprobe_core::plan::ProbePlan;

use crate::inspect::TargetSnapshot;

/// Exact refusal reason: pack experiment T6 + Phase B receipts (R-030).
pub const REFUSED_REASON: &str =
    "token/broker mode requires pack experiment T6 + Phase B receipts (R-030)";

/// Broker-mode authority that always refuses (honest stub).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenBrokerStub;

impl TokenBrokerStub {
    /// The single refusal value shared by every stub method.
    fn refused() -> BackendError {
        BackendError::Unsupported(UnsupportedReason::new(REFUSED_REASON))
    }

    /// Broker-shaped allowlist query (pre-facet signature, not the
    /// `BpfLoadAuthority` method); always refuses (R-030).
    pub fn allowed_programs() -> Result<&'static [ProgramId], BackendError> {
        Err(Self::refused())
    }

    /// Broker-shaped load op (SECURITY §3.1); always refuses (R-030).
    pub fn load_program(&self, _id: ProgramId) -> Result<(), BackendError> {
        Err(Self::refused())
    }

    /// Broker-shaped attach op (SECURITY §3.2); always refuses (R-030).
    ///
    /// `Tree`/`Cgroup` plans refuse here too (same receipt): broker mode
    /// never silently lacks fan-out policy (X15).
    pub fn attach_plan(&self, _plan: &ProbePlan) -> Result<(), BackendError> {
        Err(Self::refused())
    }

    /// Broker-shaped inspect op (SECURITY §3.3); always refuses (R-030).
    ///
    /// Unlike the facet path this reports `BackendError` (not `InspectError`)
    /// so broker callers receive the R-030 receipt pointer.
    pub fn inspect(&self, _pid: u32) -> Result<TargetSnapshot, BackendError> {
        Err(Self::refused())
    }
}
