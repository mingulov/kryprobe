// SPDX-License-Identifier: GPL-3.0-or-later
//! Observation-session state machine (ARCH §4.1).
//!
//! One linear chain plus a failure escape: any pre-terminal state may move
//! to `FailedPartial`, which may only move to `Finalized`. `Finalized` is
//! terminal. Illegal hops return [`SessionError::IllegalTransition`]; the
//! controller never panics and never moves on a refused hop.

use std::fmt::{Display, Formatter};

/// Session lifecycle state: 8 ARCH states + `FailedPartial`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Session created, not yet qualified.
    Created,
    /// Capabilities, authority, and policy qualified.
    Qualified,
    /// Discovering targets and objects.
    Discovering,
    /// Attaching probes per validated plans.
    Attaching,
    /// Observing live executions.
    Observing,
    /// Stopping new work before drain.
    Quiescing,
    /// Draining queued events into evidence.
    Draining,
    /// Evidence finalized; terminal.
    Finalized,
    /// A backend failed but the session contract permits partial results.
    FailedPartial,
}

/// Rejected session transition; the controller stays in `from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Hop from `from` to `to` is not a legal edge.
    IllegalTransition {
        /// State the controller remains in.
        from: SessionState,
        /// Requested state.
        to: SessionState,
    },
}

impl Display for SessionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal session transition: {from:?} -> {to:?}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

/// Returns true only for the 15 legal edges of the machine.
fn is_legal(from: SessionState, to: SessionState) -> bool {
    use SessionState as S;
    matches!(
        (from, to),
        (S::Created, S::Qualified)
            | (S::Qualified, S::Discovering)
            | (S::Discovering, S::Attaching)
            | (S::Attaching, S::Observing)
            | (S::Observing, S::Quiescing)
            | (S::Quiescing, S::Draining)
            | (S::Draining, S::Finalized)
            | (S::FailedPartial, S::Finalized)
            | (
                S::Created
                    | S::Qualified
                    | S::Discovering
                    | S::Attaching
                    | S::Observing
                    | S::Quiescing
                    | S::Draining,
                S::FailedPartial
            )
    )
}

/// Owns one observation session and its state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionController {
    state: SessionState,
}

impl SessionController {
    /// A new controller always starts in `Created`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SessionState::Created,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Move to `to` on a legal edge; otherwise refuse without moving.
    pub fn transition(&mut self, to: SessionState) -> Result<(), SessionError> {
        if is_legal(self.state, to) {
            self.state = to;
            Ok(())
        } else {
            Err(SessionError::IllegalTransition {
                from: self.state,
                to,
            })
        }
    }
}

impl Default for SessionController {
    fn default() -> Self {
        Self::new()
    }
}
