// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-session budget enforcement (ARCH §4.9).
//!
//! Every budget kind has its own distinct counter; exhausting one never
//! affects the others. A charge that would exceed a limit is refused
//! without consuming anything and reports a typed [`BudgetOmission`].

use crate::plan::PlanBudget;
use std::fmt::{Display, Formatter};

/// One distinct budget counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetKind {
    /// Targets admitted.
    Targets,
    /// Objects tracked.
    Objects,
    /// Payload bytes retained.
    Bytes,
    /// Attachment links held.
    Links,
    /// BPF state-table entries held.
    StateEntries,
    /// Queued events held.
    Queue,
    /// Observation duration in monotonic nanoseconds.
    Duration,
}

/// Typed record of a budget refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetOmission {
    /// Which counter ran out.
    pub kind: BudgetKind,
    /// Ceiling that was enforced.
    pub limit: u64,
    /// Amount already consumed.
    pub used: u64,
    /// Amount the refused charge requested.
    pub requested: u64,
}

impl Display for BudgetOmission {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "budget exhausted: {:?} (used {} of {}, requested {})",
            self.kind, self.used, self.limit, self.requested
        )
    }
}

impl std::error::Error for BudgetOmission {}

/// Index of a kind into the distinct counter arrays.
const fn index(kind: BudgetKind) -> usize {
    match kind {
        BudgetKind::Targets => 0,
        BudgetKind::Objects => 1,
        BudgetKind::Bytes => 2,
        BudgetKind::Links => 3,
        BudgetKind::StateEntries => 4,
        BudgetKind::Queue => 5,
        BudgetKind::Duration => 6,
    }
}

/// Enforces one session's [`PlanBudget`] with distinct counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetManager {
    limits: [u64; 7],
    used: [u64; 7],
}

impl BudgetManager {
    /// Fresh counters, all zero, with ceilings from the plan.
    #[must_use]
    pub const fn new(budget: PlanBudget) -> Self {
        Self {
            limits: [
                budget.max_targets,
                budget.max_objects,
                budget.max_bytes,
                budget.max_links,
                budget.max_state_entries,
                budget.max_queue,
                budget.max_duration_ns,
            ],
            used: [0; 7],
        }
    }

    /// Ceiling for one kind.
    #[must_use]
    pub const fn limit(&self, kind: BudgetKind) -> u64 {
        self.limits[index(kind)]
    }

    /// Amount consumed so far for one kind.
    #[must_use]
    pub const fn used(&self, kind: BudgetKind) -> u64 {
        self.used[index(kind)]
    }

    /// Consume `amount` of `kind`, or refuse with a typed omission.
    ///
    /// A refused charge consumes nothing.
    pub fn charge(&mut self, kind: BudgetKind, amount: u64) -> Result<(), BudgetOmission> {
        let slot = index(kind);
        let next = self.used[slot].saturating_add(amount);
        if next > self.limits[slot] {
            return Err(BudgetOmission {
                kind,
                limit: self.limits[slot],
                used: self.used[slot],
                requested: amount,
            });
        }
        self.used[slot] = next;
        Ok(())
    }
}
