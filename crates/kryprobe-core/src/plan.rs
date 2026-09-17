// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated probe plans (CONTRACTS §4).
//!
//! A plan is immutable once validated and serializable for
//! evidence/debugging. Backends propose; the attachment runtime validates.

use crate::enums::BackendId;
use crate::ids::PlanGeneration;
use crate::object::ObjectRef;
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

/// One file-offset probe: where to attach and how to correlate events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OffsetProbe {
    /// File offset of the probe point.
    pub file_offset: u64,
    /// Cookie stamped on events from this probe.
    pub cookie: u64,
    /// Backend callback descriptor this probe implements.
    pub descriptor_id: u32,
}

/// Target population a plan is allowed to attach to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetScope {
    /// A run owned (spawned) by KryProbe itself.
    OwnedRun,
    /// One explicit process ID.
    Pid {
        /// Process ID to attach to.
        pid: u32,
    },
    /// A process tree.
    Tree {
        /// Root process ID of the tree.
        root: u32,
    },
    /// A cgroup subtree.
    Cgroup {
        /// Cgroup filesystem path.
        path: String,
    },
}

/// Budget ceilings carried by a plan; enforced per counter at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanBudget {
    /// Maximum targets admitted.
    pub max_targets: u64,
    /// Maximum objects tracked.
    pub max_objects: u64,
    /// Maximum payload bytes retained.
    pub max_bytes: u64,
    /// Maximum attachment links held.
    pub max_links: u64,
    /// Maximum state-table entries held.
    pub max_state_entries: u64,
    /// Maximum queued events held.
    pub max_queue: u64,
    /// Maximum observation duration, monotonic nanoseconds.
    pub max_duration_ns: u64,
}

/// Runtime capabilities a plan requires before attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct CapabilityRequirements {
    /// Multi-attach uprobes must be available.
    pub uprobe_multi: bool,
    /// BPF cookie support must be available.
    pub cookies: bool,
    /// Ring-buffer transport must be available.
    pub ringbuf: bool,
    /// Kernel BTF must be present.
    pub btf: bool,
}

/// Validated, immutable probe plan for one backend and object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePlan {
    /// Backend this plan attaches.
    pub backend: BackendId,
    /// Plan generation; a new generation invalidates in-flight old state.
    pub generation: PlanGeneration,
    /// Allowed attachment population.
    pub target_scope: TargetScope,
    /// Object file the probes attach to.
    pub object: ObjectRef,
    /// Probe points, in attachment order.
    pub offsets: Vec<OffsetProbe>,
    /// Capabilities required before attachment.
    pub required_capabilities: CapabilityRequirements,
    /// Budget ceilings enforced at runtime.
    pub budget: PlanBudget,
}

impl ProbePlan {
    /// Structural validation: non-empty probes and a usable scope.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(!self.offsets.is_empty(), "plan has no offset probes");
        if let TargetScope::Cgroup { path } = &self.target_scope {
            ensure!(!path.is_empty(), "cgroup scope has an empty path");
        }
        Ok(())
    }
}

/// Serialize helper used by the round-trip test and evidence writers.
pub fn to_canonical_json(plan: &ProbePlan) -> anyhow::Result<String> {
    serde_json::to_string(plan).context("defect: ProbePlan must stay serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{CallKind, OperationClass};
    use crate::object::ObjectRole;

    fn sample_plan() -> ProbePlan {
        ProbePlan {
            backend: BackendId::OpenSsl,
            generation: PlanGeneration::new(3),
            target_scope: TargetScope::Pid { pid: 4242 },
            object: ObjectRef {
                dev: 1,
                ino: 2,
                size: 4096,
                mtime: 1_700_000_000_000_000_000,
                role: ObjectRole::SharedLibrary,
            },
            offsets: vec![
                OffsetProbe {
                    file_offset: 0x10,
                    cookie: 0xabc,
                    descriptor_id: 7,
                },
                OffsetProbe {
                    file_offset: 0x20,
                    cookie: 0xabd,
                    descriptor_id: 9,
                },
            ],
            required_capabilities: CapabilityRequirements {
                ringbuf: true,
                ..CapabilityRequirements::default()
            },
            budget: PlanBudget {
                max_targets: 8,
                max_objects: 16,
                max_bytes: 1 << 20,
                max_links: 32,
                max_state_entries: 1024,
                max_queue: 512,
                max_duration_ns: 60_000_000_000,
            },
        }
    }

    #[test]
    fn plan_json_roundtrip() {
        let plan = sample_plan();
        assert!(plan.validate().is_ok());
        let text = match to_canonical_json(&plan) {
            Ok(text) => text,
            Err(err) => panic!("plan must serialize: {err}"),
        };
        let back: ProbePlan = match serde_json::from_str(&text) {
            Ok(back) => back,
            Err(err) => panic!("plan must deserialize: {err}"),
        };
        assert_eq!(back, plan);
        assert!(text.contains("\"openssl\""), "{text}");
        assert!(text.contains("\"plan_generation:3\""), "{text}");
        // Wire spellings stay frozen-schema exact (spot check).
        assert!(matches!(
            serde_json::to_string(&OperationClass::KeyAgreement).as_deref(),
            Ok("\"key_agreement\"")
        ));
        assert!(matches!(
            serde_json::to_string(&CallKind::SizeQuery).as_deref(),
            Ok("\"size_query\"")
        ));
    }

    #[test]
    fn plan_validation_rejects_empty_probes_and_scope() {
        let mut plan = sample_plan();
        plan.offsets.clear();
        assert!(plan.validate().is_err());
        let mut plan = sample_plan();
        plan.target_scope = TargetScope::Cgroup {
            path: String::new(),
        };
        assert!(plan.validate().is_err());
    }
}
