// SPDX-License-Identifier: GPL-3.0-or-later
//! Session envelope records: `session_start` / `session_end`.

use crate::CONTRACT_VERSION_V0;
use crate::writer::{JsonlWriter, ReportError};
use kryprobe_core::enums::{BackendId, CaptureMode, TargetSelector};
use serde::Serialize;

/// Session verdict (schema `verdict` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionVerdict {
    /// Session completed within its declared boundary.
    Observed,
    /// Session completed with recorded gaps.
    Partial,
    /// Declared boundary is not supported.
    Unsupported,
    /// Session refused (policy or capability).
    Refused,
    /// Session failed.
    Failed,
}

/// Final barrier state (schema `final_barrier` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FinalBarrier {
    /// End-of-stream barrier observed and checked.
    Validated,
    /// Barrier missing (truncated session).
    Missing,
}

/// `session_start` payload; `contract_version` is always
/// [`CONTRACT_VERSION_V0`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStart {
    /// Population selector used to start the session.
    pub target_selector: TargetSelector,
    /// Capture depth requested.
    pub capture_mode: CaptureMode,
    /// Backends requested (never `Synthetic`: no wire spelling).
    pub requested_backends: Vec<BackendId>,
    /// Qualification identity for this run.
    pub qualification_id: String,
}

/// `session_end` payload; exit/signal are schema-ranged or null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    /// Session verdict.
    pub verdict: SessionVerdict,
    /// Final barrier state.
    pub final_barrier: FinalBarrier,
    /// Gap record ids still unresolved at end.
    pub unresolved_gap_ids: Vec<String>,
    /// Child exit code 0–255, or `None` for null.
    pub child_exit_code: Option<i32>,
    /// Child signal 1–128, or `None` for null.
    pub child_signal: Option<i32>,
}

#[derive(Serialize)]
struct StartPayload<'a> {
    target_selector: TargetSelector,
    capture_mode: CaptureMode,
    requested_backends: &'a [BackendId],
    contract_version: &'static str,
    qualification_id: &'a str,
}

#[derive(Serialize)]
struct EndPayload<'a> {
    verdict: SessionVerdict,
    final_barrier: FinalBarrier,
    unresolved_gap_ids: &'a [String],
    child_exit_code: Option<i32>,
    child_signal: Option<i32>,
}

impl JsonlWriter {
    /// Appends `session_start`; rejects `Synthetic` backends (no spelling).
    pub fn session_start(&mut self, start: &SessionStart) -> Result<(), ReportError> {
        if start
            .requested_backends
            .iter()
            .any(|b| b.as_wire_str().is_none())
        {
            return Err(ReportError::SyntheticBackend);
        }
        self.emit(
            "session_start",
            StartPayload {
                target_selector: start.target_selector,
                capture_mode: start.capture_mode,
                requested_backends: &start.requested_backends,
                contract_version: CONTRACT_VERSION_V0,
                qualification_id: &start.qualification_id,
            },
        )?;
        Ok(())
    }

    /// Appends `session_end`; exit/signal outside schema range fail closed.
    pub fn session_end(&mut self, end: &SessionEnd) -> Result<(), ReportError> {
        if let Some(code) = end.child_exit_code
            && !(0..=255).contains(&code)
        {
            return Err(ReportError::ExitCodeOutOfRange(code));
        }
        if let Some(sig) = end.child_signal
            && !(1..=128).contains(&sig)
        {
            return Err(ReportError::SignalOutOfRange(sig));
        }
        self.emit(
            "session_end",
            EndPayload {
                verdict: end.verdict,
                final_barrier: end.final_barrier,
                unresolved_gap_ids: &end.unresolved_gap_ids,
                child_exit_code: end.child_exit_code,
                child_signal: end.child_signal,
            },
        )?;
        Ok(())
    }
}
