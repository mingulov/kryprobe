// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated probe plans (CONTRACTS §4).
//!
//! A plan is immutable once validated and serializable for
//! evidence/debugging. Backends propose; the attachment runtime validates.

use crate::enums::BackendId;
use crate::ids::PlanGeneration;
use crate::object::ObjectRef;
use serde::{Deserialize, Serialize};

/// One file-offset probe: where to attach and how to correlate events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OffsetProbe {
    /// File offset of the probe point.
    pub file_offset: u64,
    /// Cookie stamped on events from this probe. Cookies live in the
    /// allocator-owned namespace ([`CookieAllocator`](crate::attach::CookieAllocator));
    /// until the plan→attach bridge mints them, backends propose values
    /// and the attach runtime is the source of truth.
    pub cookie: u64,
    /// Backend callback descriptor this probe implements.
    pub descriptor_id: u32,
}

/// Target population a plan is allowed to attach to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// The whole machine: system-wide kernel probes (kcrypto fentry),
    /// no pid/tree/cgroup filter. Skips fan-out (nothing to enumerate);
    /// carries no path by construction, so attachment never reads one.
    /// Report-time context still attributes each observation (pid, comm,
    /// cgroup id); the scope itself selects all (kp2 §3).
    System,
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

impl PlanBudget {
    /// Wide-open budget: every ceiling at `u64::MAX` (1B-H1/1B-L2 —
    /// the one open budget for sessions that gate on privilege/BTF,
    /// not on budgets: driver harness and live session alike).
    #[must_use]
    pub const fn open() -> Self {
        Self {
            max_targets: u64::MAX,
            max_objects: u64::MAX,
            max_bytes: u64::MAX,
            max_links: u64::MAX,
            max_state_entries: u64::MAX,
            max_queue: u64::MAX,
            max_duration_ns: u64::MAX,
        }
    }
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

/// Structural plan rejection: empty probes or an empty cgroup path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanValidationError {
    /// The plan carries no offset probes.
    NoOffsetProbes,
    /// A cgroup-scoped plan carries an empty path.
    EmptyCgroupPath,
}

impl std::fmt::Display for PlanValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoOffsetProbes => write!(f, "plan has no offset probes"),
            Self::EmptyCgroupPath => write!(f, "cgroup scope has an empty path"),
        }
    }
}

impl std::error::Error for PlanValidationError {}

impl ProbePlan {
    /// Structural validation: non-empty probes and a usable scope.
    ///
    /// Descriptor/cookie validity is owned by backends at attach time;
    /// this check only guards plan shape (CONTRACTS §4 requires no more).
    pub fn validate(&self) -> Result<(), PlanValidationError> {
        if self.offsets.is_empty() {
            return Err(PlanValidationError::NoOffsetProbes);
        }
        if let TargetScope::Cgroup { path } = &self.target_scope
            && path.is_empty()
        {
            return Err(PlanValidationError::EmptyCgroupPath);
        }
        Ok(())
    }
}

/// Plan serialization defect: `ProbePlan` must stay serializable.
/// Unreachable in practice (every field serializes); typed so callers
/// match on a defect instead of an untyped `anyhow` (M6 bar).
#[derive(Debug)]
pub struct PlanSerializeError {
    source: serde_json::Error,
}

impl std::fmt::Display for PlanSerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "defect: ProbePlan must stay serializable: {}",
            self.source
        )
    }
}

impl std::error::Error for PlanSerializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Serialize helper used by the round-trip test and evidence writers.
pub fn to_canonical_json(plan: &ProbePlan) -> Result<String, PlanSerializeError> {
    serde_json::to_string(plan).map_err(|source| PlanSerializeError { source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{CallKind, OperationClass};
    use crate::object::ObjectRole;

    #[test]
    fn open_budget_has_no_ceiling() {
        // 1B-H1/1B-L2: the one wide-open budget (driver harness + live
        // session both gate on privilege/BTF, not on budgets).
        let budget = PlanBudget::open();
        for ceiling in [
            budget.max_targets,
            budget.max_objects,
            budget.max_bytes,
            budget.max_links,
            budget.max_state_entries,
            budget.max_queue,
            budget.max_duration_ns,
        ] {
            assert_eq!(ceiling, u64::MAX);
        }
    }

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
    fn system_scope_validates_and_roundtrips_without_path() {
        // Select-all: a System plan carries no pid, root, or cgroup path
        // (unit variant: a path is inexpressible), validates, and keeps
        // its spelling across the canonical JSON round-trip.
        let mut plan = sample_plan();
        plan.target_scope = TargetScope::System;
        assert!(plan.validate().is_ok());
        let text = to_canonical_json(&plan).expect("plan must serialize");
        let back: ProbePlan = serde_json::from_str(&text).expect("plan must deserialize");
        assert_eq!(back, plan);
        assert_eq!(back.target_scope, TargetScope::System);
        assert!(text.contains("\"System\""), "{text}");
    }

    #[test]
    fn plan_validation_rejects_empty_probes_and_scope() {
        let mut plan = sample_plan();
        plan.offsets.clear();
        assert_eq!(plan.validate(), Err(PlanValidationError::NoOffsetProbes));
        let mut plan = sample_plan();
        plan.target_scope = TargetScope::Cgroup {
            path: String::new(),
        };
        assert_eq!(plan.validate(), Err(PlanValidationError::EmptyCgroupPath));
    }

    #[test]
    fn serialize_error_is_typed_with_source() {
        use serde::ser::Error as _;
        let err = PlanSerializeError {
            source: serde_json::Error::custom("boom"),
        };
        assert_eq!(
            err.to_string(),
            "defect: ProbePlan must stay serializable: boom"
        );
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn plan_validation_messages_stay_stable() {
        assert_eq!(
            PlanValidationError::NoOffsetProbes.to_string(),
            "plan has no offset probes"
        );
        assert_eq!(
            PlanValidationError::EmptyCgroupPath.to_string(),
            "cgroup scope has an empty path"
        );
    }
}
