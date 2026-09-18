// SPDX-License-Identifier: GPL-3.0-or-later
//! Integrity model: nine loss/corruption counters, default zero.
//!
//! Follows CONTRACTS §9. Aggregate counters can stay exact while detailed
//! events go partial; these counters are the receipts that prove it.

use serde::{Deserialize, Serialize};

/// Session integrity counters; `Default` is all zeros (CONTRACTS §9).
///
/// Per-backend summaries carry only backend-observed counters; the session
/// total is [`IntegritySummary::rollup`], defined once here. Backends must
/// never echo session state into their summaries (two echoes would
/// double-count under the rollup).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct IntegritySummary {
    /// Ring-buffer reservation failures.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub ring_reservation_failures: u64,
    /// Userspace queue drops.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub user_queue_drops: u64,
    /// Backend state-table insert failures.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub state_insert_failures: u64,
    /// Backend state-table evictions.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub state_evictions: u64,
    /// Entry observations without a matching return.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub unmatched_entries: u64,
    /// Return observations without a matching entry.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub unmatched_returns: u64,
    /// Correlation-state overflows.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub correlation_overflows: u64,
    /// Events from unknown plan/process generations.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub unknown_generation_events: u64,
    /// Omissions forced by budget exhaustion.
    #[serde(with = "crate::evidence::wire::u64_string")]
    pub budget_omissions: u64,
}

impl IntegritySummary {
    /// Field-wise saturating sum: the one counter-addition primitive.
    /// Saturates at `u64::MAX` per counter (counters never wrap, never
    /// panic); [`IntegritySummary::rollup`] folds through this.
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            ring_reservation_failures: self
                .ring_reservation_failures
                .saturating_add(other.ring_reservation_failures),
            user_queue_drops: self.user_queue_drops.saturating_add(other.user_queue_drops),
            state_insert_failures: self
                .state_insert_failures
                .saturating_add(other.state_insert_failures),
            state_evictions: self.state_evictions.saturating_add(other.state_evictions),
            unmatched_entries: self
                .unmatched_entries
                .saturating_add(other.unmatched_entries),
            unmatched_returns: self
                .unmatched_returns
                .saturating_add(other.unmatched_returns),
            correlation_overflows: self
                .correlation_overflows
                .saturating_add(other.correlation_overflows),
            unknown_generation_events: self
                .unknown_generation_events
                .saturating_add(other.unknown_generation_events),
            budget_omissions: self.budget_omissions.saturating_add(other.budget_omissions),
        }
    }

    /// Session rollup over per-backend counters: field-wise saturating sum.
    ///
    /// This is the one rollup site: the driver and all future consumers
    /// total per-backend summaries through this, never through ad-hoc
    /// folds. Saturates at `u64::MAX` per counter (counters never wrap);
    /// the empty rollup is zero (no backends, no observed loss).
    /// Shared-layer losses are not per-backend sums: they accrue once
    /// outside this, via [`SharedLosses`] fed to the driver report.
    #[must_use]
    pub fn rollup<'a, I>(summaries: I) -> Self
    where
        I: IntoIterator<Item = &'a IntegritySummary>,
    {
        summaries
            .into_iter()
            .fold(Self::default(), |total, summary| {
                total.saturating_add(*summary)
            })
    }
}

/// Shared-layer losses: ring/queue/drain counters observed in privilege
/// land, outside any backend (BPF `LOSS[0]` ringbuf reservation failures
/// plus the drain thread's userspace queue drops).
///
/// Ownership: the sole producer is the drain→driver path (privilege
/// `drain::DrainStats` supplies both observation points in one value);
/// the sole consumer is
/// [`DriverReport::feed_shared_losses`](crate::backend::DriverReport::feed_shared_losses),
/// which accrues it once outside the per-backend sums. The restricted
/// shape is deliberate: the shared transport can observe only these two
/// counters, so backend-scoped counters are inexpressible here and can
/// never double-count through the shared path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SharedLosses {
    /// Ringbuf reservation failures (BPF `LOSS[0]`).
    pub ring_reservation_failures: u64,
    /// Userspace queue drops (drain thread).
    pub user_queue_drops: u64,
}

impl SharedLosses {
    /// Shared losses observed outside any backend: BPF-side ring
    /// reservation failures plus drain-side queue drops.
    #[must_use]
    pub const fn new(ring_reservation_failures: u64, user_queue_drops: u64) -> Self {
        Self {
            ring_reservation_failures,
            user_queue_drops,
        }
    }
}

impl From<SharedLosses> for IntegritySummary {
    /// Map the shared counters onto the session shape; every
    /// backend-scoped counter stays zero (the shared layer observes no
    /// backend state, matching, correlation, or budget events).
    fn from(shared: SharedLosses) -> Self {
        Self {
            ring_reservation_failures: shared.ring_reservation_failures,
            user_queue_drops: shared.user_queue_drops,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IntegritySummary, SharedLosses};

    #[test]
    fn saturating_add_combines_disjoint_counters_exactly() {
        let first = IntegritySummary {
            ring_reservation_failures: 3,
            unmatched_entries: 1,
            ..IntegritySummary::default()
        };
        let second = IntegritySummary {
            user_queue_drops: 7,
            budget_omissions: 2,
            ..IntegritySummary::default()
        };
        assert_eq!(
            first.saturating_add(second),
            IntegritySummary {
                ring_reservation_failures: 3,
                user_queue_drops: 7,
                unmatched_entries: 1,
                budget_omissions: 2,
                ..IntegritySummary::default()
            }
        );
    }

    #[test]
    fn saturating_add_saturates_per_counter() {
        let high = IntegritySummary {
            ring_reservation_failures: u64::MAX,
            user_queue_drops: 40,
            ..IntegritySummary::default()
        };
        let low = IntegritySummary {
            ring_reservation_failures: 1,
            user_queue_drops: 2,
            ..IntegritySummary::default()
        };
        assert_eq!(
            high.saturating_add(low),
            IntegritySummary {
                ring_reservation_failures: u64::MAX,
                user_queue_drops: 42,
                ..IntegritySummary::default()
            }
        );
    }

    #[test]
    fn shared_losses_map_to_integrity_only_shared_counters() {
        let shared = SharedLosses::new(11, 5);
        assert_eq!(
            IntegritySummary::from(shared),
            IntegritySummary {
                ring_reservation_failures: 11,
                user_queue_drops: 5,
                ..IntegritySummary::default()
            }
        );
        assert_eq!(
            IntegritySummary::from(SharedLosses::default()),
            IntegritySummary::default()
        );
    }

    #[test]
    fn rollup_sums_disjoint_counters_exactly_once() {
        let first = IntegritySummary {
            ring_reservation_failures: 3,
            unmatched_entries: 1,
            ..IntegritySummary::default()
        };
        let second = IntegritySummary {
            user_queue_drops: 7,
            budget_omissions: 2,
            ..IntegritySummary::default()
        };
        assert_eq!(
            IntegritySummary::rollup([&first, &second]),
            IntegritySummary {
                ring_reservation_failures: 3,
                user_queue_drops: 7,
                unmatched_entries: 1,
                budget_omissions: 2,
                ..IntegritySummary::default()
            }
        );
    }

    #[test]
    fn rollup_saturates_instead_of_wrapping() {
        let high = IntegritySummary {
            ring_reservation_failures: u64::MAX,
            ..IntegritySummary::default()
        };
        let low = IntegritySummary {
            ring_reservation_failures: 1,
            user_queue_drops: 1,
            ..IntegritySummary::default()
        };
        assert_eq!(
            IntegritySummary::rollup([&high, &low]),
            IntegritySummary {
                ring_reservation_failures: u64::MAX,
                user_queue_drops: 1,
                ..IntegritySummary::default()
            }
        );
    }

    #[test]
    fn empty_rollup_is_zero() {
        let none: [&IntegritySummary; 0] = [];
        assert_eq!(IntegritySummary::rollup(none), IntegritySummary::default());
    }
}
