// SPDX-License-Identifier: GPL-3.0-or-later
#![warn(missing_docs)]
//! Explicit-rules policy engine over `NativeObservation` (K3 Task 3).
//!
//! Policies are YAML (`version: 1` + `rules`) with unknown-key rejection;
//! [`evaluate`] folds deny/report rules over one capture into a 3-state
//! [`PolicyVerdict`] (kp2 §8/`check`, D7).

pub mod eval;
pub mod glob;
pub mod rule;

pub use eval::{PolicyVerdict, evaluate};
pub use rule::{Decision, MatchSpec, Policy, PolicyError, Rule, Stage, parse_policy, parse_rule};
