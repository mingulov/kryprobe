// SPDX-License-Identifier: GPL-3.0-or-later
//! Refused token/broker authority stub (SECURITY §3, R-030).
//!
//! `TokenBrokerStub` mirrors the `LocalPrivilegedAuthority` inherent method
//! names so broker-mode call sites typecheck, but every method refuses with
//! `BackendError::Unsupported` carrying the R-030 receipt pointer. There is
//! no partial broker path: token mode arrives with pack experiment T6 +
//! Phase B receipts.

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

    /// Mirrors the local allowlist query; always refuses (R-030).
    pub fn allowed_programs() -> Result<&'static [ProgramId], BackendError> {
        Err(Self::refused())
    }

    /// Mirrors the local load op (SECURITY §3.1); always refuses (R-030).
    pub fn load_program(&self, _id: ProgramId) -> Result<(), BackendError> {
        Err(Self::refused())
    }

    /// Mirrors the local attach op (SECURITY §3.2); always refuses (R-030).
    pub fn attach_plan(&self, _plan: &ProbePlan) -> Result<(), BackendError> {
        Err(Self::refused())
    }

    /// Mirrors the local inspect op (SECURITY §3.3); always refuses (R-030).
    ///
    /// Unlike the local path this reports `BackendError` (not `InspectError`)
    /// so broker callers receive the R-030 receipt pointer.
    pub fn inspect(&self, _pid: u32) -> Result<TargetSnapshot, BackendError> {
        Err(Self::refused())
    }
}
