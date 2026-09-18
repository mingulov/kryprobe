// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure attach/drain/loss types for the BPF spine pipeline (T7a).

use crate::ids::PlanGeneration;
use crate::object::ObjectRef;
use crate::plan::TargetScope;
use crate::program::ProgramId;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// One raw multi-attach link group: (object, program, scope, entry/return, generation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkGroup {
    pub object: ObjectRef,
    pub program: ProgramId,
    pub scope: TargetScope,
    /// True for entry probes, false for return probes.
    pub entry: bool,
    /// Generation this group's cookies stamp in the high 32 bits.
    /// Issuance-only like the base: it rides the [`CookieRange`] at
    /// construction, so no post-hoc mutation can mismatch it against
    /// the range (the attach boundary's stale-guard backstop stays).
    generation: PlanGeneration,
    /// First cookie index of this group's allocator-issued range; the
    /// attach runtime stamps cookies `(generation << 32) | (base + i)`
    /// for offsets `0..len` and rejects `base + len > COUNT_SLOTS`.
    /// Issuance-only: constructible solely through
    /// [`LinkGroup::from_range`], so no hand-built base can collide
    /// with another group's slots.
    index_base: u32,
}

impl LinkGroup {
    /// Build a group over an allocator-issued range: the only
    /// construction path. Generation and base both ride the range, so
    /// the group's stamp always matches its issuance and a stray base
    /// is inexpressible.
    #[must_use]
    pub fn from_range(
        object: ObjectRef,
        program: ProgramId,
        scope: TargetScope,
        entry: bool,
        range: CookieRange,
    ) -> Self {
        Self {
            object,
            program,
            scope,
            entry,
            generation: range.generation(),
            index_base: range.base(),
        }
    }

    /// First cookie index of this group's allocator-issued range.
    #[must_use]
    pub const fn index_base(&self) -> u32 {
        self.index_base
    }

    /// Generation this group's cookies stamp (rides the issuance).
    #[must_use]
    pub const fn generation(&self) -> PlanGeneration {
        self.generation
    }

    /// Re-scope an issued group (fan-out): same issuance, new scope.
    /// Base and generation carry over untouched — members share the
    /// template's range by construction, never by re-issue.
    #[must_use]
    pub fn with_scope(&self, scope: TargetScope) -> Self {
        let mut out = self.clone();
        out.scope = scope;
        out
    }
}

/// Cookie index slots (`COUNT` map entries); the low-32-bit index space
/// shared by every link group of one generation. Frozen with the BPF
/// `COUNT_ENTRIES` and the loader's `SPINE_MAPS` COUNT dims; a privilege
/// test pins all three equal (the loader already asserts the object).
pub const COUNT_SLOTS: u32 = 64;

/// One cookie for `index` under `generation`: `(generation << 32) | index`.
///
/// The single formula site: [`CookieRange::cookies`] and the attach
/// runtime both stamp through this, so the layout cannot drift.
#[must_use]
pub fn cookie_for(generation: PlanGeneration, index: u32) -> u64 {
    (u64::from(generation.get()) << 32) | u64::from(index)
}

/// Cookie/index namespace allocator: disjoint index ranges per group.
///
/// Namespace rules:
/// - Cookie layout is `(generation << 32) | index` with `index` in
///   `0..COUNT_SLOTS` (64, frozen by the BPF `COUNT` map).
/// - One allocator serves one (session, `COUNT` map, generation); every
///   range it issues is disjoint, so concurrent groups never conflate
///   `COUNT[idx]`.
/// - Groups stamp cookies from their issued range only; the attach
///   boundary re-validates (`base + len <= COUNT_SLOTS`) and rejects.
/// - Generations partition the namespace: the BPF generation gate drops
///   stale cookies, so a new generation starts a fresh allocator and
///   safely reuses index space.
/// - Exhaustion refuses with [`CookieExhausted`]: never wraps, never
///   aliases, never partially issues, never consumes on failure.
/// - The allocator is never [`Copy`]: any copy would fork the namespace
///   and issue overlapping ranges, so duplication is explicit
///   ([`Clone::clone`], visible at the call site) or nothing.
/// - Owner: [`BackendDriver`](crate::backend::BackendDriver) holds the
///   session allocator as session state (like the ID issuer); raw attach
///   paths without a driver hold a function-local one for their single
///   generation until the plan→attach bridge routes through the driver.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CookieAllocator {
    generation: PlanGeneration,
    next: u32,
}

impl CookieAllocator {
    /// Fresh allocator for `generation`: all [`COUNT_SLOTS`] free.
    #[must_use]
    pub const fn new(generation: PlanGeneration) -> Self {
        Self {
            generation,
            next: 0,
        }
    }

    /// Generation this allocator issues for.
    #[must_use]
    pub const fn generation(&self) -> PlanGeneration {
        self.generation
    }

    /// Slots issued so far.
    #[must_use]
    pub const fn used(&self) -> u32 {
        self.next
    }

    /// Slots still free.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        COUNT_SLOTS - self.next
    }

    /// Issue a disjoint range of `len` indices, or refuse. Empty and
    /// over-size requests are `Err` and consume nothing.
    pub fn allocate(&mut self, len: usize) -> Result<CookieRange, CookieExhausted> {
        let remaining = self.remaining();
        match u32::try_from(len) {
            Ok(want) if want != 0 && want <= remaining => {
                let range = CookieRange {
                    base: self.next,
                    len: want,
                    generation: self.generation,
                };
                self.next += want;
                Ok(range)
            }
            _ => Err(CookieExhausted {
                requested: len,
                remaining,
            }),
        }
    }
}

/// One allocator-issued index range: constructible only via
/// [`CookieAllocator::allocate`], so disjointness holds by construction.
/// The range carries its issuing allocator's generation with it, so
/// cookies always stamp the issuance — never a caller-supplied value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CookieRange {
    base: u32,
    len: u32,
    generation: PlanGeneration,
}

impl CookieRange {
    /// First index of the range (the group's `LinkGroup` base).
    #[must_use]
    pub const fn base(&self) -> u32 {
        self.base
    }

    /// Indices in the range (always nonzero).
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Always false: the allocator never issues empty ranges.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Generation the issuing allocator serves: every cookie from
    /// [`CookieRange::cookies`] stamps this in the high 32 bits.
    #[must_use]
    pub const fn generation(&self) -> PlanGeneration {
        self.generation
    }

    /// Cookies for this range under the issuing allocator's generation,
    /// in index order. No caller-supplied stamp exists: a wrong stamp
    /// would alias another generation's slots or mint gate-dropped
    /// cookies, silently either way.
    #[must_use]
    pub fn cookies(&self) -> Vec<u64> {
        (0..self.len)
            .map(|i| cookie_for(self.generation, self.base + i))
            .collect()
    }
}

/// Refused index allocation: the request did not fit the free space.
/// Fail closed: the caller attaches nothing, so nothing can alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieExhausted {
    /// Requested range length.
    pub requested: usize,
    /// Slots free when refused.
    pub remaining: u32,
}

impl Display for CookieExhausted {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cookie index space exhausted: requested {} slots, {} of {COUNT_SLOTS} remain",
            self.requested, self.remaining
        )
    }
}

impl std::error::Error for CookieExhausted {}

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

/// Drain configuration rejection: zero budgets or an unrepresentable poll timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainConfigError {
    /// `max_events_per_iter` is zero.
    ZeroMaxEventsPerIter,
    /// `queue_depth` is zero.
    ZeroQueueDepth,
    /// `poll_timeout_ms` is zero.
    ZeroPollTimeout,
    /// `poll_timeout_ms` exceeds `i32::MAX` (the epoll wait takes an `i32`).
    PollTimeoutTooLarge {
        /// The rejected timeout value.
        value: u64,
    },
}

impl Display for DrainConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxEventsPerIter => write!(f, "max_events_per_iter must be nonzero"),
            Self::ZeroQueueDepth => write!(f, "queue_depth must be nonzero"),
            Self::ZeroPollTimeout => write!(f, "poll_timeout_ms must be nonzero"),
            Self::PollTimeoutTooLarge { value } => {
                write!(f, "poll_timeout_ms {value} exceeds i32::MAX")
            }
        }
    }
}

impl std::error::Error for DrainConfigError {}

impl DrainConfig {
    pub fn validate(&self) -> Result<(), DrainConfigError> {
        if self.max_events_per_iter == 0 {
            return Err(DrainConfigError::ZeroMaxEventsPerIter);
        }
        if self.queue_depth == 0 {
            return Err(DrainConfigError::ZeroQueueDepth);
        }
        if self.poll_timeout_ms == 0 {
            return Err(DrainConfigError::ZeroPollTimeout);
        }
        if self.poll_timeout_ms > i32::MAX as u64 {
            return Err(DrainConfigError::PollTimeoutTooLarge {
                value: self.poll_timeout_ms,
            });
        }
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
    Partial {
        missing: u64,
    },
    /// Over-accounted: more observed than ground truth. `excess` clamps
    /// to `u64::MAX` when hostile counters overflow `u64` — the verdict
    /// stays `Defect`, only the magnitude saturates.
    Defect {
        excess: u64,
    },
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
            // Hostile counters overflow u64: the verdict stays Defect,
            // only the magnitude clamps to u64::MAX (documented on the
            // variant).
            (
                0,
                u64::MAX,
                u64::MAX,
                ReconcileVerdict::Defect { excess: u64::MAX },
            ),
            (
                5,
                u64::MAX,
                u64::MAX,
                ReconcileVerdict::Defect { excess: u64::MAX },
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
        for (bad, want) in [
            (
                DrainConfig {
                    max_events_per_iter: 0,
                    ..ok
                },
                DrainConfigError::ZeroMaxEventsPerIter,
            ),
            (
                DrainConfig {
                    queue_depth: 0,
                    ..ok
                },
                DrainConfigError::ZeroQueueDepth,
            ),
            (
                DrainConfig {
                    poll_timeout_ms: 0,
                    ..ok
                },
                DrainConfigError::ZeroPollTimeout,
            ),
        ] {
            assert_eq!(bad.validate(), Err(want));
        }
    }

    #[test]
    fn drain_config_messages_stay_stable() {
        assert_eq!(
            DrainConfigError::ZeroMaxEventsPerIter.to_string(),
            "max_events_per_iter must be nonzero"
        );
        assert_eq!(
            DrainConfigError::ZeroQueueDepth.to_string(),
            "queue_depth must be nonzero"
        );
        assert_eq!(
            DrainConfigError::ZeroPollTimeout.to_string(),
            "poll_timeout_ms must be nonzero"
        );
    }

    #[test]
    fn drain_config_rejects_poll_timeout_above_i32_max() {
        let ok = DrainConfig {
            max_events_per_iter: 128,
            queue_depth: 1024,
            poll_timeout_ms: i32::MAX as u64,
        };
        assert!(ok.validate().is_ok());
        let bad = DrainConfig {
            poll_timeout_ms: i32::MAX as u64 + 1,
            ..ok
        };
        assert_eq!(
            bad.validate(),
            Err(DrainConfigError::PollTimeoutTooLarge {
                value: i32::MAX as u64 + 1,
            })
        );
        let huge = DrainConfig {
            poll_timeout_ms: u64::MAX,
            ..ok
        };
        assert_eq!(
            huge.validate(),
            Err(DrainConfigError::PollTimeoutTooLarge { value: u64::MAX })
        );
    }

    #[test]
    fn link_group_from_range_carries_issuance() {
        use crate::object::ObjectRole;
        let mut alloc = CookieAllocator::new(PlanGeneration::new(3));
        alloc.allocate(5).expect("skip to base 5");
        let range = alloc.allocate(1).expect("group range fits");
        let group = LinkGroup::from_range(
            ObjectRef {
                dev: 1,
                ino: 2,
                size: 4096,
                mtime: 1_700_000_000_000_000_000,
                role: ObjectRole::SharedLibrary,
            },
            ProgramId::UprobeMultiSelfProbe,
            TargetScope::Pid { pid: 4242 },
            true,
            range,
        );
        // Generation AND base ride the issuance: the constructor takes
        // no caller-supplied stamp or base, so neither can be smuggled.
        assert_eq!(group.generation(), PlanGeneration::new(3));
        assert_eq!(group.index_base(), 5);
    }

    #[test]
    fn link_group_serde_roundtrip() {
        use crate::object::ObjectRole;
        let mut alloc = CookieAllocator::new(PlanGeneration::new(3));
        alloc.allocate(5).expect("skip to base 5");
        let range = alloc.allocate(1).expect("group range fits");
        let group = LinkGroup::from_range(
            ObjectRef {
                dev: 1,
                ino: 2,
                size: 4096,
                mtime: 1_700_000_000_000_000_000,
                role: ObjectRole::SharedLibrary,
            },
            ProgramId::UprobeMultiSelfProbe,
            TargetScope::Pid { pid: 4242 },
            true,
            range,
        );
        let text = serde_json::to_string(&group).expect("LinkGroup must serialize");
        assert!(text.contains("UprobeMultiSelfProbe"), "{text}");
        assert!(text.contains("index_base"), "{text}");
        let back: LinkGroup = serde_json::from_str(&text).expect("LinkGroup must deserialize");
        assert_eq!(back, group);
    }

    #[test]
    fn link_group_with_scope_preserves_issuance() {
        use crate::object::ObjectRole;
        let mut alloc = CookieAllocator::new(PlanGeneration::new(3));
        alloc.allocate(5).expect("skip to base 5");
        let range = alloc.allocate(1).expect("group range fits");
        let group = LinkGroup::from_range(
            ObjectRef {
                dev: 1,
                ino: 2,
                size: 4096,
                mtime: 1_700_000_000_000_000_000,
                role: ObjectRole::SharedLibrary,
            },
            ProgramId::UprobeMultiSelfProbe,
            TargetScope::Pid { pid: 4242 },
            true,
            range,
        );
        // Re-scoping (fan-out) carries the issuance untouched — the
        // generation and base accessors observe the same values, and
        // the field being private means no caller can mutate either
        // post-hoc (enforced at compile time; this test pins the
        // read path).
        let rescoped = group.with_scope(TargetScope::Pid { pid: 7 });
        assert_eq!(rescoped.scope, TargetScope::Pid { pid: 7 });
        assert_eq!(rescoped.generation(), PlanGeneration::new(3));
        assert_eq!(rescoped.index_base(), 5);
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
