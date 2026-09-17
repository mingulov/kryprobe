// SPDX-License-Identifier: GPL-3.0-or-later
//! Observed-target catalog records: selector, identity, validity interval.

use crate::enums::TargetSelector;
use crate::ids::{ProcessGeneration, TargetId};
use serde::{Deserialize, Serialize};

/// One observed target: how it was selected and when the record holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRecord {
    /// Session-scoped target identity.
    pub id: TargetId,
    /// Selector that admitted this target.
    pub selector: TargetSelector,
    /// Observed process ID, when known.
    pub observed_pid: Option<u32>,
    /// Observed thread ID, when known.
    pub observed_tid: Option<u32>,
    /// Process lifetime generation (fork/exec aware).
    pub process_generation: ProcessGeneration,
    /// Executable image generation (exec/re-exec aware).
    pub executable_generation: u64,
    /// Start of validity, monotonic nanoseconds.
    pub valid_from_ns: u64,
    /// End of validity, or `None` while still valid.
    pub valid_until_ns: Option<u64>,
    /// Free-text omission notes attached to this record.
    pub omissions: Vec<String>,
}
