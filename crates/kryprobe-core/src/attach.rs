// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure attach/drain/loss types for the BPF spine pipeline (T7a).

use crate::ids::PlanGeneration;
use crate::object::ObjectRef;
use crate::plan::TargetScope;
use crate::program::ProgramId;
use anyhow::ensure;
use serde::{Deserialize, Serialize};

/// One raw multi-attach link group: (object, program, scope, entry/return, generation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkGroup {
    pub object: ObjectRef,
    pub program: ProgramId,
    pub scope: TargetScope,
    /// True for entry probes, false for return probes.
    pub entry: bool,
    pub generation: PlanGeneration,
}

/// Pins the generation of in-flight work; older generations are stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenerationGuard {
    pub generation: PlanGeneration,
}

impl GenerationGuard {
    pub fn is_stale(&self, current: PlanGeneration) -> bool {
        self.generation != current
    }
}

/// Userspace drain-thread budgets; all three must be nonzero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DrainConfig {
    pub max_events_per_iter: u64,
    pub queue_depth: u64,
    pub poll_timeout_ms: u64,
}

impl DrainConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.max_events_per_iter != 0,
            "max_events_per_iter must be nonzero"
        );
        ensure!(self.queue_depth != 0, "queue_depth must be nonzero");
        ensure!(self.poll_timeout_ms != 0, "poll_timeout_ms must be nonzero");
        Ok(())
    }
}

/// Loss accounting: exact ground truth vs received + drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LossLedger {
    pub exact: u64,
    pub received: u64,
    pub drops: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReconcileVerdict {
    Clean,
    Partial { missing: u64 },
    Defect { excess: u64 },
}

impl LossLedger {
    /// Reconcile without ever overflow-panicking on hostile counters.
    pub fn reconcile(&self) -> ReconcileVerdict {
        if self.received.checked_add(self.drops).is_none() {
            let excess = (self.received as u128 + self.drops as u128 - self.exact as u128)
                .min(u64::MAX as u128) as u64;
            return ReconcileVerdict::Defect { excess };
        }
        let accounted = self.received.saturating_add(self.drops);
        if accounted == self.exact {
            ReconcileVerdict::Clean
        } else if accounted < self.exact {
            ReconcileVerdict::Partial {
                missing: self.exact - accounted,
            }
        } else {
            ReconcileVerdict::Defect {
                excess: accounted - self.exact,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_table() {
        let cases = [
            (100, 100, 0, ReconcileVerdict::Clean),
            (100, 90, 10, ReconcileVerdict::Clean),
            (100, 80, 10, ReconcileVerdict::Partial { missing: 10 }),
            (100, 95, 10, ReconcileVerdict::Defect { excess: 5 }),
            (0, 0, 0, ReconcileVerdict::Clean),
            (
                u64::MAX,
                u64::MAX,
                1,
                ReconcileVerdict::Defect { excess: 1 },
            ),
        ];
        for (exact, received, drops, want) in cases {
            let ledger = LossLedger {
                exact,
                received,
                drops,
            };
            let got = ledger.reconcile();
            assert_eq!(got, want, "exact={exact} received={received} drops={drops}");
        }
    }

    #[test]
    fn drain_config_validate() {
        let ok = DrainConfig {
            max_events_per_iter: 128,
            queue_depth: 1024,
            poll_timeout_ms: 50,
        };
        assert!(ok.validate().is_ok());
        for bad in [
            DrainConfig {
                max_events_per_iter: 0,
                ..ok
            },
            DrainConfig {
                queue_depth: 0,
                ..ok
            },
            DrainConfig {
                poll_timeout_ms: 0,
                ..ok
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }

    #[test]
    fn link_group_serde_roundtrip() {
        use crate::object::ObjectRole;
        let group = LinkGroup {
            object: ObjectRef {
                dev: 1,
                ino: 2,
                size: 4096,
                mtime: 1_700_000_000_000_000_000,
                role: ObjectRole::SharedLibrary,
            },
            program: ProgramId::UprobeMultiSelfProbe,
            scope: TargetScope::Pid { pid: 4242 },
            entry: true,
            generation: PlanGeneration::new(3),
        };
        let text = serde_json::to_string(&group).expect("LinkGroup must serialize");
        assert!(text.contains("UprobeMultiSelfProbe"), "{text}");
        let back: LinkGroup = serde_json::from_str(&text).expect("LinkGroup must deserialize");
        assert_eq!(back, group);
    }

    #[test]
    fn generation_guard() {
        let guard = GenerationGuard {
            generation: PlanGeneration::new(3),
        };
        assert!(!guard.is_stale(PlanGeneration::new(3)));
        assert!(guard.is_stale(PlanGeneration::new(4)));
    }
}
