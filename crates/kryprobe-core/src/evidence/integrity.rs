// SPDX-License-Identifier: GPL-3.0-or-later
//! Integrity model: nine loss/corruption counters, default zero.
//!
//! Follows CONTRACTS §9. Aggregate counters can stay exact while detailed
//! events go partial; these counters are the receipts that prove it.

use serde::{Deserialize, Serialize};

/// Session integrity counters; `Default` is all zeros (CONTRACTS §9).
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
