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
    /// Session rollup over per-backend counters: field-wise saturating sum.
    ///
    /// This is the one rollup site: the driver and all future consumers
    /// total per-backend summaries through this, never through ad-hoc
    /// folds. Saturates at `u64::MAX` per counter (counters never wrap);
    /// the empty rollup is zero (no backends, no observed loss).
    #[must_use]
    pub fn rollup<'a, I>(summaries: I) -> Self
    where
        I: IntoIterator<Item = &'a IntegritySummary>,
    {
        let mut total = Self::default();
        for summary in summaries {
            total.ring_reservation_failures = total
                .ring_reservation_failures
                .saturating_add(summary.ring_reservation_failures);
            total.user_queue_drops = total
                .user_queue_drops
                .saturating_add(summary.user_queue_drops);
            total.state_insert_failures = total
                .state_insert_failures
                .saturating_add(summary.state_insert_failures);
            total.state_evictions = total
                .state_evictions
                .saturating_add(summary.state_evictions);
            total.unmatched_entries = total
                .unmatched_entries
                .saturating_add(summary.unmatched_entries);
            total.unmatched_returns = total
                .unmatched_returns
                .saturating_add(summary.unmatched_returns);
            total.correlation_overflows = total
                .correlation_overflows
                .saturating_add(summary.correlation_overflows);
            total.unknown_generation_events = total
                .unknown_generation_events
                .saturating_add(summary.unknown_generation_events);
            total.budget_omissions = total
                .budget_omissions
                .saturating_add(summary.budget_omissions);
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::IntegritySummary;

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
