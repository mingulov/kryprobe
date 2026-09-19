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
    /// Attribution-only execution-context cgroup id (cgroupfs id number),
    /// recorded at report time, when known. Never an attach filter and
    /// never a path: [`TargetScope::System`](crate::plan::TargetScope::System)
    /// attaches with no cgroup path (kp2 §3), and this number is where
    /// the cgroup context still lands per observation.
    pub cgroup_id: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::TargetRecord;
    use crate::enums::TargetSelector;
    use crate::ids::{ProcessGeneration, TargetId};

    #[test]
    fn system_record_keeps_attribution_cgroup_id() {
        // System scope selects all at attach (no pid/tree/path filter),
        // but the report-time record still attributes the execution
        // context: observed ids plus the cgroup id number (never a path).
        let record = TargetRecord {
            id: TargetId::new(7),
            selector: TargetSelector::System,
            observed_pid: Some(4242),
            observed_tid: Some(4242),
            cgroup_id: Some(12345),
            process_generation: ProcessGeneration::new(1),
            executable_generation: 1,
            valid_from_ns: 100,
            valid_until_ns: None,
            omissions: Vec::new(),
        };
        let text = serde_json::to_string(&record).expect("record must serialize");
        let back: TargetRecord = serde_json::from_str(&text).expect("record must deserialize");
        assert_eq!(back, record);
        assert_eq!(back.selector, TargetSelector::System);
        assert_eq!(back.cgroup_id, Some(12345));
        assert!(text.contains("\"system\""), "{text}");
        assert!(text.contains("12345"), "{text}");
    }
}
